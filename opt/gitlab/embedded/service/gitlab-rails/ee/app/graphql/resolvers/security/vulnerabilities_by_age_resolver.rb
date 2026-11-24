# frozen_string_literal: true

module Resolvers
  module Security
    class VulnerabilitiesByAgeResolver < VulnerabilitiesBaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include LooksAhead

      type [Types::Security::VulnerabilitiesByAgeType], null: true

      authorize :read_security_resource

      argument :severity, [Types::VulnerabilitySeverityEnum],
        required: false,
        description: 'Filter vulnerabilities by severity.'

      def resolve_with_lookahead(**args)
        authorize!(object) unless resolve_vulnerabilities_for_instance_security_dashboard?
        validate_advanced_vuln_management!

        base_params = build_base_params(args)

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
        lookahead.selects?(field_name)
      end

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
        states = Vulnerability.active_states
        resolved_on_default_branch = false

        {
          state: states,
          has_resolution: resolved_on_default_branch
        }
      end

      def fetch_grouped_results(params)
        finder = ::Search::AdvancedFinders::Security::Vulnerability::CountByAgeFinder.new(vulnerable, params)
        finder.execute
      end

      def transform_results(severity_results, report_type_results)
        return [] if severity_results.empty? && report_type_results.empty?

        age_band_map = {}

        unless severity_results.empty?
          process_results(severity_results, age_band_map) do |result, entry|
            entry[:by_severity] = transform_severity_data(result[:by_severity])
          end
        end

        unless report_type_results.empty?
          process_results(report_type_results, age_band_map) do |result, entry|
            entry[:by_report_type] = transform_report_type_data(result[:by_report_type])
          end
        end

        age_band_map.values.select do |entry|
          entry[:by_severity].any? || entry[:by_report_type].any?
        end
      end

      def get_value(hash, key)
        return unless hash

        hash[key.to_s] || hash[key]
      end

      def process_results(results, age_band_map)
        results.each do |result|
          age_band_name = get_value(result, :name)
          next unless age_band_name

          age_band_key = age_band_name.to_s

          age_band_map[age_band_key] ||= {
            name: age_band_name,
            count: 0,
            by_severity: [],
            by_report_type: []
          }

          count = result[:count]
          age_band_map[age_band_key][:count] = count if age_band_map[age_band_key][:count] == 0

          yield(result, age_band_map[age_band_key]) if block_given?
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
