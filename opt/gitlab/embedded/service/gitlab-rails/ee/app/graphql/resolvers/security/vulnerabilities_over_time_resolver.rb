# frozen_string_literal: true

module Resolvers
  module Security
    class VulnerabilitiesOverTimeResolver < VulnerabilitiesBaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include LooksAhead

      MAX_DATE_RANGE_DAYS = 31

      type Types::Security::VulnerabilitiesOverTimeType.connection_type, null: true

      authorize :read_security_resource

      argument :start_date, GraphQL::Types::ISO8601Date,
        required: true,
        description: 'Start date for the vulnerability metrics time range.'

      argument :end_date, GraphQL::Types::ISO8601Date,
        required: true,
        description: 'End date for the vulnerability metrics time range. ' \
          'The end date should be within 31 days from the start date.'

      argument :severity, [Types::VulnerabilitySeverityEnum],
        required: false,
        description: 'Filter vulnerabilities by severity.'

      def resolve_with_lookahead(start_date:, end_date:, **args)
        authorize!(object) unless resolve_vulnerabilities_for_instance_security_dashboard?
        validate_advanced_vuln_management!
        validate_date_range!(start_date, end_date)

        base_params = build_base_params(start_date, end_date, args)

        # Check which fields are requested
        severity_requested = field_requested?(:by_severity)
        report_type_requested = field_requested?(:by_report_type)

        severity_results = if severity_requested
                             fetch_grouped_results(base_params.merge(group_by: 'severity'))
                           else
                             []
                           end

        report_type_results = if report_type_requested
                                fetch_grouped_results(base_params.merge(group_by: 'report_type'))
                              else
                                []
                              end

        transform_results(severity_results, report_type_results)
      end

      private

      def field_requested?(field_name)
        lookahead.selection(:nodes).selects?(field_name)
      end

      def build_base_params(start_date, end_date, args)
        project_ids = context[:project_id]
        report_type = context[:report_type]
        tracked_context_id = context[:tracked_ref_ids]

        {
          created_after: start_date,
          created_before: end_date,
          project_id: project_ids,
          report_type: report_type,
          severity: args[:severity],
          security_project_tracked_context_id: tracked_context_id
        }.compact
      end

      def fetch_grouped_results(params)
        finder = ::Search::AdvancedFinders::Security::Vulnerability::CountOverTimeFinder.new(vulnerable, params)
        finder.execute
      end

      def validate_date_range!(start_date, end_date)
        raise Gitlab::Graphql::Errors::ArgumentError, "start date cannot be after end date" if start_date > end_date

        return unless (end_date - start_date) > MAX_DATE_RANGE_DAYS

        raise Gitlab::Graphql::Errors::ArgumentError, "maximum date range is #{MAX_DATE_RANGE_DAYS} days"
      end

      def transform_results(severity_results, report_type_results)
        return [] if severity_results.empty? && report_type_results.empty?

        date_map = {}

        unless severity_results.empty?
          process_results(severity_results, date_map) do |result, entry|
            entry[:by_severity] = transform_severity_data(result[:by_severity])
          end
        end

        unless report_type_results.empty?
          process_results(report_type_results, date_map) do |result, entry|
            entry[:by_report_type] = transform_report_type_data(result[:by_report_type])
          end
        end

        date_map.values.select do |entry|
          entry[:by_severity].any? || entry[:by_report_type].any?
        end
      end

      def get_value(hash, key)
        return unless hash

        hash[key.to_s] || hash[key]
      end

      def process_results(results, date_map)
        results.each do |result|
          date_value = get_value(result, :date)
          next unless date_value

          date_key = date_value.to_s

          date_map[date_key] ||= {
            date: date_value,
            count: 0,
            by_severity: [],
            by_report_type: []
          }

          count = result[:count]
          date_map[date_key][:count] = count if date_map[date_key][:count] == 0

          yield(result, date_map[date_key]) if block_given?
        end
      end

      def transform_grouped_data(data, field_name)
        return [] unless data

        data.map do |item|
          value = get_value(item, field_name)
          value = value.downcase if value.is_a?(String)

          {
            field_name.to_sym => value,
            count: get_value(item, :count).to_i
          }
        end
      end

      def transform_severity_data(severity_data)
        transform_grouped_data(severity_data, :severity)
      end

      def transform_report_type_data(report_type_data)
        transform_grouped_data(report_type_data, :report_type)
      end
    end
  end
end
