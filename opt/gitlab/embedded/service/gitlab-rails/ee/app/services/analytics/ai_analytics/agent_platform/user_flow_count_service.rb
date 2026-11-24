# frozen_string_literal: true

module Analytics
  module AiAnalytics
    module AgentPlatform
      # rubocop: disable CodeReuse/ActiveRecord -- Not ActiveRecord
      class UserFlowCountService
        include CommonUsageService

        FIELDS =
          %i[flow_type sessions_count user].freeze

        private

        def success_payload
          usage_data
        end

        def empty_payload
          []
        end

        def usage_data
          ClickHouse::Client.select(query, :main)
        end

        # Sample query
        #
        # SELECT `sessions`.`flow_type`, `sessions`.`user_id`, uniq(`sessions`.`session_id`) AS sessions_count
        # FROM (
        #   SELECT flow_type, user_id, session_id
        #   FROM agent_platform_sessions
        #   WHERE startsWith(namespace_path, '9970/')
        #     AND session_year = 2025
        #   GROUP BY flow_type, user_id, session_id
        #   HAVING toDate(anyIfMerge(created_event_at)) >= '2025-11-27'
        #     AND toDate(anyIfMerge(created_event_at)) <= '2025-11-27'
        # ) sessions
        # GROUP BY flow_type, user_id
        # ORDER BY sessions_count DESC, user_id ASC, flow_type ASC
        def query
          sessions = ClickHouse::Client::QueryBuilder.new(sessions_in_range, 'sessions')

          sessions
            .select(*projections_for(sessions.table))
            .group(:flow_type, :user_id)
            .order(Arel.sql('sessions_count'), :desc)
            .order(:user_id, :asc)
            .order(:flow_type, :asc)
        end

        # Grouping by session merges its rows (the table splits a session across year partitions),
        # so the date filter sees each session's own creation time; merging per user first would
        # pick one arbitrary session's date for all of them.
        def sessions_in_range
          builder = ClickHouse::Client::QueryBuilder.new('agent_platform_sessions')
          table = builder.table

          created_at_date = Arel::Nodes::NamedFunction.new('toDate', [
            Arel::Nodes::NamedFunction.new('anyIfMerge', [table[:created_event_at]])
          ])

          namespace_filter =
            Arel::Nodes::NamedFunction.new('startsWith',
              [Arel.sql('namespace_path'),
                Arel::Nodes.build_quoted(namespace.traversal_path(with_organization: false))])

          builder
            .select(:flow_type, :user_id, :session_id)
            .where(namespace_filter)
            .where(table[:session_year].between(from.to_date.year..to.to_date.year))
            .group(:flow_type, :user_id, :session_id)
            .having(created_at_date.gteq(from.to_date.iso8601))
            .having(created_at_date.lteq(to.to_date.iso8601))
        end

        def projections_for(table)
          sessions_count =
            Arel::Nodes::NamedFunction.new('uniq', [table[:session_id]]).as('sessions_count')

          [:flow_type, :user_id, sessions_count]
        end
      end
      # rubocop: enable CodeReuse/ActiveRecord
    end
  end
end
