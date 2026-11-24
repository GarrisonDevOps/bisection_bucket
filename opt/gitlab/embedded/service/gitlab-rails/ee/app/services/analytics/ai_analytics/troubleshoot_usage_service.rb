# frozen_string_literal: true

module Analytics
  module AiAnalytics
    class TroubleshootUsageService
      include CommonUsageService

      QUERY = <<~SQL.freeze
        SELECT COUNT(DISTINCT user_id) as root_cause_analysis_users_count
        FROM ai_usage_events
        WHERE timestamp >= {from:Date}
        AND timestamp <= {to:Date}
        AND startsWith(traversal_path, {traversal_path:String})
        AND event = #{Ai::UsageEvent.events['troubleshoot_job']}
      SQL

      FIELDS_SUBQUERIES = {
        root_cause_analysis_users_count: QUERY
      }.freeze

      FIELDS = FIELDS_SUBQUERIES.keys

      private

      def scope_traversal_path
        namespace.traversal_path(with_organization: true)
      end
    end
  end
end
