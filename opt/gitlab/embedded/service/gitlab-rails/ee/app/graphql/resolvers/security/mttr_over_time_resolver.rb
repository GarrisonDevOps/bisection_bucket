# frozen_string_literal: true

module Resolvers
  module Security
    class MttrOverTimeResolver < VulnerabilitiesBaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include LooksAhead

      # Defined inside the aggregations module's `class << self`, so it lives on the singleton class.
      MAX_WEEKS = ::Search::Elastic::VulnerabilityAggregations.singleton_class::MTTR_OVER_TIME_MAX_WEEKS
      DETECTION_WINDOW_DAYS =
        ::Search::Elastic::VulnerabilityAggregations.singleton_class::MTTR_OVER_TIME_DETECTION_WINDOW.in_days.to_i
      DETECTION_WINDOW_NOTE = "Each week only counts vulnerabilities detected no earlier than " \
        "#{DETECTION_WINDOW_DAYS} days before the week starts, " \
        "so a week's MTTR is at most about #{DETECTION_WINDOW_DAYS + 7} days.".freeze

      type [::Types::Security::MttrOverTimeBucketType], null: true

      authorize :read_security_resource

      argument :start_date, GraphQL::Types::ISO8601Date,
        required: true,
        description: 'Start date of the time range. Snapped back to the start of its week (Monday) ' \
          'so results align to full Monday to Sunday buckets.'

      argument :end_date, GraphQL::Types::ISO8601Date,
        required: true,
        description: 'End date of the time range. Snapped forward to the end of its week (Sunday), ' \
          'capped at the current date. The most recent week may be partial. ' \
          "The range can span at most #{MAX_WEEKS} weeks."

      argument :severity, [Types::VulnerabilitySeverityEnum],
        required: false,
        description: 'Filter vulnerabilities by severity.'

      def resolve_with_lookahead(start_date:, end_date:, **args)
        return unless Feature.enabled?(:security_dashboard_mttr_chart, object || current_user)

        authorize!(object) unless resolve_vulnerabilities_for_instance_security_dashboard?
        validate_advanced_vuln_management!
        validate_date_range!(start_date, end_date)

        ::Search::AdvancedFinders::Security::Vulnerability::MttrOverTimeFinder
          .new(vulnerable, finder_params(start_date, end_date, args))
          .execute
      end

      private

      def finder_params(start_date, end_date, args)
        {
          created_after: start_date,
          created_before: end_date,
          group_mttr_by: group_mttr_by,
          project_id: context[:project_id],
          report_type: context[:report_type],
          severity: args[:severity],
          security_project_tracked_context_id: context[:tracked_ref_ids]
        }.compact
      end

      # Only decides which breakdowns the single Elasticsearch query includes, never whether it runs.
      def group_mttr_by
        { 'severity' => :by_severity, 'report_type' => :by_report_type }
          .select { |_, field| lookahead.selects?(field) }
          .keys
      end

      # Mirrors the aggregation, which works in UTC and stops at the current week.
      def validate_date_range!(start_date, end_date)
        today = Time.current.utc.to_date
        raise Gitlab::Graphql::Errors::ArgumentError, "start date cannot be after end date" if start_date > end_date
        raise Gitlab::Graphql::Errors::ArgumentError, "start date cannot be in the future" if start_date > today

        last_monday = [end_date, today].min.beginning_of_week(:monday)
        weeks = ((last_monday - start_date.beginning_of_week(:monday)).to_i / 7) + 1
        return if weeks <= MAX_WEEKS

        raise Gitlab::Graphql::Errors::ArgumentError, "maximum date range is #{MAX_WEEKS} weeks"
      end
    end
  end
end
