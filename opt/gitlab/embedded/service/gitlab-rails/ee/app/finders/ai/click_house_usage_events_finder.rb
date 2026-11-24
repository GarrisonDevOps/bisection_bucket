# frozen_string_literal: true

module Ai
  class ClickHouseUsageEventsFinder < BaseUsageEventsFinder
    # rubocop:disable CodeReuse/ActiveRecord -- Not ActiveRecord but Clickhouse query builder

    # Includes traversal_path so the query-time deduplication groups by the table's sort key.
    # namespace_path stays projected because it backs the AiInstanceUsageEvent GraphQL field.
    GROUPING_COLUMNS = %i[namespace_path traversal_path event timestamp user_id].freeze

    def execute
      query = build_base_query
      query = apply_filters(query)
      query.group(*GROUPING_COLUMNS)
           .order(:timestamp, :desc)
           .order(:user_id, :desc)
    end

    private

    def build_base_query
      builder = ClickHouse::Client::QueryBuilder.new('ai_usage_events')
      projections = build_projections(builder)
      builder.select(*projections)
    end

    def build_projections(builder)
      projections = GROUPING_COLUMNS.map { |column| builder.table[column] }
      projections << extras_projection(builder)
      projections
    end

    def extras_projection(builder)
      node = Arel::Nodes::NamedFunction.new('argMax', [builder[:extras], builder[:timestamp]])
      node.as('extras')
    end

    def apply_filters(query)
      query = filter_by_timeframe(query)
      query = filter_by_events(query) if events&.any?
      query = filter_by_users(query) if users&.any?
      query = filter_by_namespace(query) if namespace
      query
    end

    def filter_by_timeframe(query)
      query.where(query.table[:timestamp].gteq(format_timestamp(from)))
           .where(query.table[:timestamp].lteq(format_timestamp(to)))
    end

    def filter_by_events(query)
      event_ids = events.filter_map { |event| ::Ai::UsageEvent.events[event] }
      return query if event_ids.empty?

      query.where(event: event_ids)
    end

    def filter_by_users(query)
      return query if users.empty?

      query.where(user_id: users)
    end

    def filter_by_namespace(query)
      query.where(
        Arel::Nodes::NamedFunction.new('startsWith', [
          query.table[:traversal_path],
          Arel::Nodes.build_quoted(namespace.traversal_path(with_organization: true).to_s)
        ])
      )
    end

    def format_timestamp(time)
      time.to_time.utc.strftime('%Y-%m-%d %H:%M:%S')
    end
  end
  # rubocop:enable CodeReuse/ActiveRecord
end
