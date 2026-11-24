# frozen_string_literal: true

# Security::ScanResultPolicies::GroupedFindingsEvaluator
#
# Returns `Security::Finding` UUIDs for a given pipeline with support for
# atomic scanner rule criteria. It handles scanner-specific vulnerability_attributes,
# severity_levels, vulnerabilities_allowed, and vulnerability_states by grouping scanners
# with the same attributes and executing batched queries.

module Security
  module ScanResultPolicies
    class GroupedFindingsEvaluator
      include GroupedEvaluatorConcern

      GroupResult = Struct.new(:uuids, :vulnerabilities_allowed, :vulnerability_states, :dependency_filtered,
        keyword_init: true)

      def initialize(project, pipeline, params = {})
        @project = project
        @pipeline = pipeline
        @params = params
      end

      attr_reader :pipeline

      def grouped_results
        return unless scanner_configurations.present?

        execute_grouped_queries
      end

      private

      def execute_grouped_queries
        grouped_scanners = group_scanners_by_attributes

        return [] if grouped_scanners.empty?

        grouped_scanners.flat_map do |attributes, scanner_types|
          results = [standard_group_result(scanner_types, attributes)]
          results.unshift(malicious_group_result(scanner_types)) if malicious_path?(attributes)
          results
        end
      end

      def standard_group_result(scanner_types, attributes)
        finder_params = build_finder_params(scanner_types, attributes)
        findings = FindingsFinder.new(project, pipeline, finder_params).execute
        # Only the source evaluator gets a filter, so target findings keep the newly detected baseline.
        dependency_filtered = params[:dependency_filter].present? &&
          attributes.values_at(:dependency_change, :dependency_type).any?

        uuids = if dependency_filtered
                  params[:dependency_filter].filter(
                    findings.distinct_context_unaware_uuids_with_location,
                    dependency_change: attributes[:dependency_change],
                    dependency_type: attributes[:dependency_type]
                  )
                else
                  findings.distinct_context_unaware_uuids
                end

        GroupResult.new(
          uuids: uuids,
          vulnerabilities_allowed: attributes[:vulnerabilities_allowed],
          vulnerability_states: attributes[:vulnerability_states],
          dependency_filtered: dependency_filtered
        )
      end

      # Supersede path: when a scanner is flagged as malicious, any malware finding blocks
      # the merge request regardless of the rule's other vulnerability-attribute settings.
      # This is enforced as an OR alongside the standard filters by emitting a separate
      # GroupResult that omits the severity/state filters and sets vulnerabilities_allowed: 0.
      #
      # The `dismissed` filter is intentionally omitted here too: a malware finding must block
      # even when dismissed, so the malicious path deliberately ignores dismissal.
      def malicious_group_result(scanner_types)
        finder_params = {
          scanners: scanner_types,
          malicious: true,
          related_pipeline_ids: params[:related_pipeline_ids]
        }.compact
        uuids = FindingsFinder.new(project, pipeline, finder_params).execute.distinct_context_unaware_uuids

        GroupResult.new(uuids: uuids, vulnerabilities_allowed: 0, vulnerability_states: nil)
      end

      def malicious_path?(attributes)
        attributes[:is_malicious] == true
      end

      def group_key_mapping
        {
          severity_levels: :severity_levels,
          vulnerability_states: :vulnerability_states,
          vulnerabilities_allowed: :vulnerabilities_allowed,
          is_malicious: :is_malicious,
          dependency_change: :dependency_change,
          dependency_type: :dependency_type
        }
      end

      def build_finder_params(scanner_types, group_attributes)
        vulnerability_attributes_from(group_attributes).merge(
          scanners: scanner_types,
          severity_levels: group_attributes[:severity_levels],
          dismissed: params[:dismissed],
          related_pipeline_ids: params[:related_pipeline_ids]
        ).compact
      end
    end
  end
end
