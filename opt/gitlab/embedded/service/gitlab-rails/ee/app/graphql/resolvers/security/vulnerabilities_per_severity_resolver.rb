# frozen_string_literal: true

module Resolvers
  module Security
    class VulnerabilitiesPerSeverityResolver < VulnerabilitiesBaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type Types::Security::VulnerabilitiesPerSeverityType, null: true

      authorize :read_security_resource

      argument :start_date, GraphQL::Types::ISO8601Date,
        required: false,
        experiment: { milestone: '18.3' },
        description: 'Start date for the vulnerability metrics time range. Optional.'

      argument :end_date, GraphQL::Types::ISO8601Date,
        required: false,
        experiment: { milestone: '18.3' },
        description: 'End date for the vulnerability metrics time range. Optional.'

      def resolve(start_date: nil, end_date: nil)
        authorize!(object) unless resolve_vulnerabilities_for_instance_security_dashboard?

        validate_advanced_vuln_management!

        validate_date_range!(start_date, end_date)

        return {} unless vulnerable

        params = build_base_params(start_date, end_date)

        fetch_results(params)
      end

      private

      def validate_date_range!(start_date, end_date)
        if start_date.present? ^ end_date.present? # XOR - only one is present
          raise Gitlab::Graphql::Errors::ArgumentError,
            "both start_date and end_date must be either nil or both must be present"
        elsif start_date.present? && end_date.present? && start_date > end_date
          raise Gitlab::Graphql::Errors::ArgumentError, "start date cannot be after end date"
        end
      end

      def calculate_mean_age(aggregations)
        avg_ms = aggregations.dig('avg_detected_at', 'value')
        return unless avg_ms

        avg_detected_at = Time.at(avg_ms / 1000)
        (Time.current - avg_detected_at) / 1.day
      end

      def calculate_median_age(aggregations)
        median_ms = aggregations.dig('median_detected_at', 'values', '50.0')
        return unless median_ms

        median_detected_at = Time.at(median_ms / 1000)
        (Time.current - median_detected_at) / 1.day
      end

      def build_base_params(start_date, end_date)
        project_ids = context[:project_id]
        report_type = context[:report_type]
        tracked_context_id = context[:tracked_ref_ids]

        {
          created_after: start_date,
          created_before: end_date,
          project_id: project_ids,
          report_type: report_type,
          security_project_tracked_context_id: tracked_context_id
        }.merge(default_filters)
      end

      # To include only active and exclude no longer detected vulnerabilities.
      def default_filters
        states = Vulnerability.active_states
        resolved_on_default_branch = false

        {
          state: states,
          has_resolution: resolved_on_default_branch
        }
      end

      def fetch_results(params)
        finder = ::Search::AdvancedFinders::Security::Vulnerability::CountBySeverityFinder.new(vulnerable, params)
        results = finder.execute

        ::Enums::Vulnerability.severity_levels.each_key.index_with do |severity|
          severity_data = results[severity.to_s] || {}
          {
            count: severity_data['count'] || 0,
            mean_age: calculate_mean_age(severity_data),
            median_age: calculate_median_age(severity_data)
          }
        end
      end
    end
  end
end
