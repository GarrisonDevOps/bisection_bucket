# frozen_string_literal: true

module Resolvers
  module Security
    class VulnerabilitiesByIdentifierResolver < VulnerabilitiesBaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include LooksAhead

      type [Types::Security::VulnerabilitiesByIdentifierType], null: true

      authorize :read_security_resource

      argument :severity, [Types::VulnerabilitySeverityEnum],
        required: false,
        description: 'Filter vulnerabilities by severity.'

      def resolve_with_lookahead(**args)
        authorize!(object) unless resolve_vulnerabilities_for_instance_security_dashboard?
        validate_advanced_vuln_management!

        params = build_base_params(args)
        fetch_results(params)
      end

      private

      def build_base_params(args)
        project_ids = context[:project_id]
        report_type = context[:report_type]
        tracked_context_id = context[:tracked_ref_ids]

        {
          project_id: project_ids,
          report_type: report_type,
          severity: args[:severity],
          security_project_tracked_context_id: tracked_context_id
        }.compact.merge(default_filters)
      end

      # To include only active and exclude no longer detected vulnerabilities.
      def default_filters
        {
          state: Vulnerability.active_states,
          has_resolution: false
        }
      end

      def fetch_results(params)
        finder = ::Search::AdvancedFinders::Security::Vulnerability::TopCwesFinder.new(vulnerable, params)
        transform_results(finder.execute)
      end

      def transform_results(results)
        return [] unless results.present?

        results.map do |result|
          {
            name: result["cwe"].upcase,
            url: cwe_url(result["cwe"]),
            count: result["count"],
            by_severity: transform_severity_data(result["by_severity"])
          }
        end
      end

      def cwe_url(cwe)
        id = cwe.split('-').last
        "https://cwe.mitre.org/data/definitions/#{id}.html"
      end

      def transform_severity_data(severity_data)
        return [] unless severity_data

        severity_data.map do |item|
          {
            severity: item["severity"].downcase,
            count: item["count"]
          }
        end
      end
    end
  end
end
