# frozen_string_literal: true

module Ai
  module Governance
    # Sessions and distinct developers per slice, plus exact totals, from the Siphon replica.
    class ClickHouseSessionDistributionService
      DUO_SOURCE = ::Ai::Governance::Session.sources.fetch(:gitlab_duo)
      DUO_NAME = 'gitlab_duo'
      FALLBACK_NAME = ::Ai::Governance::Session::DISTRIBUTION_FALLBACK_NAME

      # Older glab sessions were synced from workflows with source gitlab_duo, so agent_type marks them external.
      DUO_CONDITION = "(source = #{DUO_SOURCE} AND ifNull(agent_type, '') = '')".freeze

      FLOW_TYPE_NAME = "coalesce(nullIf(splitByChar('/', ifNull(flow_type, ''))[1], ''), '#{FALLBACK_NAME}')".freeze
      AGENT_TYPE_NAME = "coalesce(nullIf(ifNull(agent_type, ''), ''), '#{FALLBACK_NAME}')".freeze

      # agent_class => fixed SQL fragments for the slice name and the row filter.
      NAMES = {
        internal_dap: FLOW_TYPE_NAME,
        external: AGENT_TYPE_NAME,
        all: "if(#{DUO_CONDITION}, '#{DUO_NAME}', #{AGENT_TYPE_NAME})"
      }.freeze

      FILTERS = {
        internal_dap: "AND #{DUO_CONDITION}",
        external: "AND NOT #{DUO_CONDITION}",
        all: ''
      }.freeze

      # Keys on the table's primary key (traversal_path, session_started_at, id) so the
      # prefix and time bounds prune granules before argMax picks each row's latest version.
      # The empty grouping set is the total row, sorted first by grouping(name) = 1.
      QUERY = <<~SQL
        SELECT
          %{name} AS name,
          count() AS sessions,
          uniqExact(user_id) AS developers,
          grouping(name) AS is_total
        FROM (
          SELECT
            id,
            session_started_at,
            argMax(user_id, _siphon_replicated_at) AS user_id,
            argMax(source, _siphon_replicated_at) AS source,
            argMax(flow_type, _siphon_replicated_at) AS flow_type,
            argMax(agent_type, _siphon_replicated_at) AS agent_type,
            argMax(_siphon_deleted, _siphon_replicated_at) AS deleted
          FROM siphon_ai_governance_sessions
          WHERE startsWith(traversal_path, {traversal_path:String})
            AND session_started_at >= {from:DateTime64(6, 'UTC')}
            AND session_started_at < {to:DateTime64(6, 'UTC')}
          GROUP BY traversal_path, session_started_at, id
        )
        WHERE deleted = false
          %{filter}
        GROUP BY GROUPING SETS ((name), ())
        ORDER BY is_total DESC, developers DESC, sessions DESC, name ASC
        LIMIT {limit:UInt8}
      SQL

      def initialize(container, timeframe:, agent_class:, limit:)
        @container = container
        @timeframe = timeframe
        @agent_class = agent_class
        @limit = limit
      end

      def execute
        query = ClickHouse::Client::Query.new(
          raw_query: format(QUERY, name: NAMES.fetch(agent_class), filter: FILTERS.fetch(agent_class)),
          placeholders: {
            traversal_path: namespace.traversal_path(with_organization: true),
            from: format_time(timeframe.from),
            to: format_time(timeframe.to),
            limit: limit + 1
          }
        )

        totals, slices = ClickHouse::Client.select(query, :main).partition { |row| row['is_total'].to_i == 1 }
        total = totals.first || {}

        {
          total_sessions: total['sessions'].to_i,
          total_developers: total['developers'].to_i,
          slices: slices.map do |row|
            { name: row['name'], sessions: row['sessions'].to_i, developers: row['developers'].to_i }
          end
        }
      end

      private

      attr_reader :container, :timeframe, :agent_class, :limit

      def namespace
        container.is_a?(::Project) ? container.project_namespace : container
      end

      def format_time(time)
        time.utc.strftime('%Y-%m-%d %H:%M:%S.%6N')
      end
    end
  end
end
