# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class BaseUpdateService
      include ::Security::AnalyzersStatus::AggregatedTypesHandler

      TooManyProjectIdsError = Class.new(StandardError)
      MAX_PROJECT_IDS = Security::AnalyzersStatus::ScheduleSettingChangedUpdateWorker::BATCH_SIZE

      PIPELINE_ONLY_TYPES = %i[sast dependency_scanning business_logic skillguard].freeze
      PROFILE_BASED_TYPES = %i[dependency_scanning_post_processing].freeze
      PROFILE_UPDATE_TYPES = (PIPELINE_ONLY_TYPES + PROFILE_BASED_TYPES).freeze
      SETTINGS_BASED_TYPES = TYPE_MAPPINGS.keys.freeze

      def self.execute(project_ids, analyzer_type)
        new(project_ids, analyzer_type).execute
      end

      def initialize(project_ids, analyzer_type)
        if project_ids && project_ids.size > MAX_PROJECT_IDS
          raise TooManyProjectIdsError, "Cannot update analyzer statuses of more than #{MAX_PROJECT_IDS} projects"
        end

        @project_ids = project_ids
        @analyzer_type = analyzer_type.to_sym
      end

      def execute
        return unless supported? && projects.present?

        namespaces_diffs = DiffsService.new(analyzers_statuses).execute
        upsert_analyzers_statuses
        update_ancestors(namespaces_diffs)
      end

      private

      attr_reader :project_ids, :analyzer_type

      def supported?
        raise NotImplementedError
      end

      def analyzers_statuses
        raise NotImplementedError
      end

      def projects
        return [] unless project_ids.present?

        @projects ||= build_projects_relation
      end

      def build_projects_relation
        Project.id_in(project_ids)
          .with_namespaces
          .with_analyzer_statuses
          .with_security_scan_profiles
      end

      def has_applicable_profile?(project)
        # security_scan_profiles is preloaded via #build_projects_relation, so filter
        # soft-deleted profiles in memory to avoid an N+1 from a scoped query.
        project.security_scan_profiles.any? do |profile|
          !profile.deleted? && profile.scan_type.to_sym == analyzer_type
        end
      end

      def upsert_analyzers_statuses
        statuses_array = analyzers_statuses.values.flat_map(&:values)
        return unless statuses_array.present?

        AnalyzerProjectStatus.upsert_all(statuses_array, unique_by: [:project_id, :analyzer_type])
        InventoryFilters::AnalyzerStatusUpdateService.execute(projects, statuses_array)
      end

      def update_ancestors(namespaces_diffs)
        return unless namespaces_diffs.present?

        namespaces_diffs.each do |namespace_diffs|
          Security::AnalyzerNamespaceStatuses::AncestorsUpdateService.execute(namespace_diffs)
        end
      end
    end
  end
end
