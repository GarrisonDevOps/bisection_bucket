# frozen_string_literal: true

# Security::ScanResultPolicies::GroupedVulnerabilitiesEvaluator
#
# Returns `Vulnerability` records for a project with support for
# atomic scanner rule criteria. It handles scanner-specific vulnerability_attributes,
# severity_levels, vulnerabilities_allowed, and vulnerability_states by grouping scanners
# with the same attributes and executing batched queries.

module Security
  module ScanResultPolicies
    class GroupedVulnerabilitiesEvaluator
      include GroupedEvaluatorConcern

      GroupResult = Struct.new(:vulnerabilities, :vulnerabilities_allowed, :vulnerability_states, keyword_init: true)

      def initialize(project, params = {})
        @project = project
        @params = params
      end

      def grouped_results
        return unless scanner_configurations.present?

        execute_grouped_query_results
      end

      private

      def execute_grouped_query_results
        grouped_scanners = group_scanners_by_attributes

        return [] if grouped_scanners.empty?

        grouped_scanners.map do |attributes, scanner_types|
          group_limit = (attributes[:vulnerabilities_allowed] || 0) + 1
          finder_params = build_finder_params(scanner_types, attributes, group_limit)
          relation = VulnerabilitiesFinder.new(project, finder_params).execute

          GroupResult.new(
            vulnerabilities: relation,
            vulnerabilities_allowed: attributes[:vulnerabilities_allowed],
            vulnerability_states: attributes[:state]
          )
        end
      end

      def group_key_mapping
        {
          severity_levels: :severity,
          vulnerability_states: :state,
          vulnerabilities_allowed: :vulnerabilities_allowed
        }
      end

      def build_finder_params(scanner_types, group_attributes, limit)
        vulnerability_attributes_from(group_attributes).merge(
          report_type: scanner_types,
          state: group_attributes[:state],
          severity: group_attributes[:severity],
          vulnerability_age: params[:vulnerability_age],
          limit: limit
        ).compact
      end
    end
  end
end
