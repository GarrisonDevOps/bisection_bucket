# frozen_string_literal: true

module Analytics
  module AiAnalytics
    module CommonUsageService
      include Gitlab::Utils::StrongMemoize

      def initialize(current_user, namespace:, from:, to:, fields: nil)
        @current_user = current_user
        @namespace = namespace
        @from = from
        @to = to
        @fields = (fields & self.class::FIELDS) || self.class::FIELDS
      end

      def execute
        return feature_unavailable_error unless clickhouse_available?
        return ServiceResponse.success(payload: empty_payload) unless fields.present?

        ServiceResponse.success(payload: success_payload)
      end

      private

      attr_reader :current_user, :namespace, :from, :to, :fields

      def clickhouse_available?
        Gitlab::ClickHouse.enabled_for_analytics?(namespace)
      end

      def success_payload
        usage_data.symbolize_keys!
      end

      def empty_payload
        {}
      end

      def feature_unavailable_error
        ServiceResponse.error(
          message: s_('AiAnalytics|the ClickHouse data store is not available')
        )
      end

      def placeholders
        {
          traversal_path: scope_traversal_path,
          from: from.to_date.iso8601,
          to: to.to_date.iso8601
        }
      end
      strong_memoize_attr :placeholders

      # Overridden by services whose table has migrated to the org-scoped path format.
      # See https://gitlab.com/gitlab-org/gitlab/-/issues/603734
      def scope_traversal_path
        namespace.traversal_path(with_organization: false)
      end

      def usage_data
        query = ClickHouse::Client::Query.new(raw_query: raw_query, placeholders: placeholders)

        ClickHouse::Client.select(query, :main).first
      end

      def raw_query
        raw_fields = fields.map do |field|
          "(#{field_subquery(field)}) as #{field}"
        end.join(',')

        format(self.class::QUERY, fields: raw_fields)
      end

      def field_subquery(field)
        self.class::FIELDS_SUBQUERIES[field]
      end
    end
  end
end
