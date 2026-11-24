# frozen_string_literal: true

module Ai
  module Governance
    # ClickHouse twin of Ai::DuoWorkflows::Workflow.session_activity_by_agent_type over
    # external sessions in siphon_ai_governance_sessions. Sessions carrying an identity in
    # the container's hierarchy stand in for the hierarchy's identities.
    class ClickHouseConnectedAgentActivityService
      DUO_SOURCE = ::Ai::Governance::Session.sources.fetch(:gitlab_duo)

      # No lower bound: last_session_at is the last session ever, as on the PostgreSQL path.
      QUERY = <<~SQL.freeze
        SELECT
          agent_type,
          countIf(session_started_at >= {from:DateTime64(6, 'UTC')}
            AND session_started_at < {to:DateTime64(6, 'UTC')}) AS session_count,
          max(session_started_at) AS last_session_at
        FROM (
          SELECT
            id,
            session_started_at,
            argMax(source, _siphon_replicated_at) AS source,
            argMax(agent_type, _siphon_replicated_at) AS agent_type,
            argMax(agent_identity_id, _siphon_replicated_at) AS agent_identity_id,
            argMax(_siphon_deleted, _siphon_replicated_at) AS deleted
          FROM siphon_ai_governance_sessions
          WHERE startsWith(traversal_path, {traversal_path:String})
          GROUP BY traversal_path, session_started_at, id
        )
        WHERE deleted = false
          AND source != #{DUO_SOURCE}
          AND agent_identity_id IS NOT NULL
          AND agent_type IN {agent_types:Array(String)}
        GROUP BY agent_type
      SQL

      def initialize(container, timeframe:, agent_types:)
        @container = container
        @timeframe = timeframe
        @agent_types = agent_types
      end

      # { agent_type => [sessions started in [from, to), last session ever] }
      def execute
        query = ClickHouse::Client::Query.new(raw_query: QUERY, placeholders: {
          traversal_path: namespace.traversal_path(with_organization: true),
          from: format_time(timeframe.from),
          to: format_time(timeframe.to),
          agent_types: agent_types
        })

        ClickHouse::Client.select(query, :main).to_h do |row|
          [row['agent_type'], [row['session_count'].to_i, row['last_session_at'].utc]]
        end
      end

      private

      attr_reader :container, :timeframe, :agent_types

      def namespace
        container.is_a?(::Project) ? container.project_namespace : container
      end

      def format_time(time)
        time.utc.strftime('%Y-%m-%d %H:%M:%S.%6N')
      end
    end
  end
end
