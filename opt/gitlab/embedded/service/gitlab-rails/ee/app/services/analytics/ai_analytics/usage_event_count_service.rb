# frozen_string_literal: true

module Analytics
  module AiAnalytics
    class UsageEventCountService
      include CommonUsageService

      COUNT_FIELD_SUFFIX = '_event_count'

      # Supports original event names and event names with '_event_count' suffix
      FIELDS = Gitlab::Tracking::AiTracking.registered_events.keys.flat_map do |field|
        [field, "#{field}#{COUNT_FIELD_SUFFIX}"]
      end.map(&:to_sym)

      private

      def usage_data
        ClickHouse::Client.select(query, :main).first
      end

      # Sample query output
      # when selecting encounter_duo_code_review_error_during_reviem
      # and find_no_issues_duo_code_review_after_review fields
      #
      #  SELECT
      #      sumIf(occurrences, event = 10) AS encounter_duo_code_review_error_during_review,
      #      sumIf(occurrences, event = 11) AS find_no_issues_duo_code_review_after_review,
      #  FROM ai_usage_events_daily
      #  WHERE (date >= '2024-01-01')
      #   AND (date <= '2025-10-30')
      #   AND startsWith(namespace_path, '99/100')
      def query
        builder = ClickHouse::Client::QueryBuilder.new('ai_usage_events_daily')
        table = builder.table
        namespace_filter =
          Arel::Nodes::NamedFunction.new('startsWith',
            [Arel.sql('namespace_path'), Arel::Nodes.build_quoted(namespace.traversal_path(with_organization: false))])

        # rubocop: disable CodeReuse/ActiveRecord -- Not ActiveRecord
        builder
          .select(*select_fields)
          .where(table[:date].gteq(from.to_date.iso8601))
          .where(table[:date].lteq(to.to_date.iso8601))
          .where(namespace_filter)
        # rubocop: enable CodeReuse/ActiveRecord
      end

      def select_fields
        events_with_ids = Gitlab::Tracking::AiTracking.registered_events

        fields.map do |field|
          event_name = field.to_s.delete_suffix(COUNT_FIELD_SUFFIX)
          Arel::Nodes::NamedFunction.new(
            'sumIf',
            [Arel.sql("occurrences, event = #{events_with_ids[event_name]}")]
          ).as(field.to_s)
        end
      end
    end
  end
end
