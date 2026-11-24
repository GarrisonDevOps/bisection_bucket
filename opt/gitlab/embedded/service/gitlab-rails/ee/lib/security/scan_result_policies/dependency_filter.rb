# frozen_string_literal: true

# Applies the scanner-level `dependency_change` and `dependency_type` settings to
# dependency scanning findings by matching each finding's (lockfile, name, version)
# against the SBOM components of the target and source pipelines.
#
# Pipeline ids are the related ones the findings are read from, so findings and SBOMs come from the same set.
module Security
  module ScanResultPolicies
    class DependencyFilter
      include ::Gitlab::Utils::StrongMemoize

      DEPENDENCY_TYPES = %w[direct transitive].freeze

      def initialize(source_pipeline_ids:, target_pipeline_ids:)
        @source_pipeline_ids = source_pipeline_ids
        @target_pipeline_ids = target_pipeline_ids
      end

      # findings: [[uuid, location], ...]; a UUID matches when any of its rows matches.
      def filter(findings, dependency_change:, dependency_type:)
        findings.filter_map do |uuid, location|
          key = finding_key(location)
          uuid if matches_change?(key, dependency_change) && matches_type?(key, dependency_type)
        end.uniq
      end

      private

      attr_reader :source_pipeline_ids, :target_pipeline_ids

      def matches_change?(key, dependency_change)
        case dependency_change
        when 'introduced' then target_components.exclude?(key)
        when 'unchanged' then target_components.include?(key)
        else true
        end
      end

      def matches_type?(key, dependency_type)
        return true unless dependency_type

        types = source_dependency_types[key]
        types.nil? || types.include?(dependency_type)
      end

      def finding_key(location)
        location ||= {}
        [location['file'], location.dig('dependency', 'package', 'name'), location.dig('dependency', 'version')]
      end

      def target_components
        return Set.new if target_pipeline_ids.empty?

        sbom_components(target_pipeline_ids).to_set { |key, _component| key }
      end
      strong_memoize_attr :target_components

      # Unions the types every report gives a component, so an extra report can widen a match but never narrow it.
      def source_dependency_types
        sbom_components(source_pipeline_ids).each_with_object({}) do |(key, component), types|
          (types[key] ||= Set.new).merge(dependency_types(component.ancestors))
        end
      end
      strong_memoize_attr :source_dependency_types

      # Without a dependency graph the type is unknown, so the component counts as either.
      def dependency_types(ancestors)
        return DEPENDENCY_TYPES if ancestors.empty?

        ancestors.map { |ancestor| ancestor.empty? ? 'direct' : 'transitive' }.uniq
      end

      def sbom_components(pipeline_ids)
        sbom_reports(pipeline_ids).flat_map do |report|
          path = report.source&.input_file_path
          report.components.map { |component| [[path, component.name, component.version], component] }
        end
      end

      def sbom_reports(pipeline_ids)
        reports = ::Gitlab::Ci::Reports::Sbom::Reports.new
        ::Ci::Build.in_pipelines(pipeline_ids).latest.with_sbom_report_artifacts
          .each { |build| build.collect_sbom_reports!(reports) }
        reports.valid_reports
      end
    end
  end
end
