# frozen_string_literal: true

module Analytics
  module AiAnalytics
    class DuoUsageService
      include CommonUsageService

      DUO_USED_COUNT_QUERY = <<~SQL
        SELECT COUNT(DISTINCT user_id) as duo_used_count
        FROM ai_usage_events
        WHERE startsWith(traversal_path, {traversal_path:String})
          AND timestamp >= {from:Date}
          AND timestamp <= {to:Date}
      SQL
      private_constant :DUO_USED_COUNT_QUERY

      FIELDS_SUBQUERIES = {
        duo_used_count: DUO_USED_COUNT_QUERY
      }.freeze

      FIELDS = FIELDS_SUBQUERIES.keys

      private

      def usage_data
        params = {
          traversal_path: namespace.traversal_path(with_organization: true),
          from: from.to_date.iso8601,
          to: to.to_date.iso8601
        }

        query = ClickHouse::Client::Query.new(raw_query: DUO_USED_COUNT_QUERY, placeholders: params)

        ClickHouse::Client.select(query, :main).first
      end
    end
  end
end
