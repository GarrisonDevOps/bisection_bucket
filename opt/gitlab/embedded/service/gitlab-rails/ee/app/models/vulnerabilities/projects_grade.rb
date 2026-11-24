# frozen_string_literal: true

module Vulnerabilities
  class ProjectsGrade
    include Gitlab::Utils::StrongMemoize

    BATCH_SIZE = 1000

    attr_reader :vulnerable, :grade, :project_ids, :include_subgroups

    delegate :count, to: :projects

    def projects
      self.class
          .unarchived_projects_for(::Project.id_in(project_ids))
          .inc_routes
          .with_vulnerability_statistics
          .order_by_id_list(project_ids)
          .to_a
    end
    strong_memoize_attr :projects

    def self.grades_for(vulnerables, filter: nil, include_subgroups: false)
      vulnerables = normalize_vulnerables(vulnerables)

      relations_by_vulnerable = build_relations(vulnerables, include_subgroups)
      vulnerable_to_project_ids = extract_project_ids(relations_by_vulnerable)

      all_project_ids = vulnerable_to_project_ids.values.flatten.uniq
      return empty_grades_for(vulnerables) if all_project_ids.empty?

      stats_rows = aggregated_vulnerability_stats_for(all_project_ids, filter)
      grouped_stats = group_stats_by_vulnerable(vulnerable_to_project_ids, stats_rows)

      build_grades(vulnerables, grouped_stats, filter, include_subgroups)
    end

    private

    def initialize(vulnerable, letter_grade, project_ids = [], include_subgroups: false)
      @vulnerable = vulnerable
      @grade = letter_grade
      @project_ids = project_ids
      @include_subgroups = include_subgroups
    end

    def self.normalize_vulnerables(vulnerables)
      list = Array(vulnerables).compact.uniq

      raise ArgumentError, 'No vulnerable entities provided' if list.empty?

      list
    end

    def self.build_relations(vulnerables, include_subgroups)
      vulnerables.index_with do |vulnerable|
        projects_relation_for(vulnerable, include_subgroups)
      end
    end

    def self.extract_project_ids(relations_by_vulnerable)
      relations_by_vulnerable.transform_values do |relation|
        next [] unless relation

        [].tap do |ids|
          relation.select(:id).each_batch do |batch|
            ids.concat(batch.limit(BATCH_SIZE).pluck(:id))
          end
        end.uniq
      end
    end

    def self.group_stats_by_vulnerable(vulnerable_to_project_ids, stats_rows)
      grouped_stats = Hash.new { |h, k| h[k] = {} }

      stats_rows.each do |row|
        vulnerable_to_project_ids.each do |vulnerable, project_ids|
          matching = row.project_ids & project_ids
          next if matching.empty?

          grouped_stats[vulnerable][row.letter_grade] ||= []
          grouped_stats[vulnerable][row.letter_grade].concat(matching)
        end
      end

      grouped_stats
    end

    def self.build_grades(vulnerables, grouped_stats, filter, include_subgroups)
      vulnerables.index_with do |vulnerable|
        grades_hash = grouped_stats[vulnerable] || {}

        grades_to_return(filter).filter_map do |grade|
          project_ids = grades_hash[grade] || []

          next if filter && project_ids.empty?
          next if (vulnerable.is_a?(::Project) || vulnerable.respond_to?(:project)) && project_ids.empty?

          new(
            vulnerable,
            grade,
            project_ids.uniq,
            include_subgroups: include_subgroups
          )
        end
      end
    end

    def self.empty_grades_for(vulnerables)
      vulnerables.index_with { [] }
    end

    def self.projects_relation_for(vulnerable, include_subgroups)
      projects =
        if vulnerable.is_a?(::Project)
          ::Project.id_in([vulnerable.id])
        elsif include_subgroups && vulnerable.respond_to?(:all_projects)
          vulnerable.all_projects
        elsif vulnerable.respond_to?(:project)
          ::Project.id_in([vulnerable.project.id])
        elsif vulnerable.respond_to?(:projects)
          vulnerable.projects
        else
          ::Project.none
        end

      unarchived_projects_for(projects)
    end

    def self.unarchived_projects_for(projects)
      return ::Project.none unless projects.all?(::Project)

      projects.non_archived
    end

    def self.aggregated_vulnerability_stats_for(project_ids, filter)
      return [] if project_ids.empty?

      project_ids.each_slice(BATCH_SIZE).flat_map do |batch|
        stats = ::Vulnerabilities::Statistic
                  .by_projects(batch)
                  .unarchived
                  .ordered_by_severity

        stats = stats.by_grade(filter) if filter

        ::Vulnerabilities::Statistic
          .from_statistics(stats)
          .aggregate_by_grade
      end
    end

    def self.grades_to_return(filter)
      valid_grades = ::Vulnerabilities::Statistic.letter_grades.keys.map(&:to_s)
      filter.present? && valid_grades.include?(filter.to_s) ? [filter.to_s] : valid_grades
    end

    private_class_method :new
  end
end
