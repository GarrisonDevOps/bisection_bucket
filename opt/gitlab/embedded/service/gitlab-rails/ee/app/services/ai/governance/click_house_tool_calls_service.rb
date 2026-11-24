# frozen_string_literal: true

module Ai
  module Governance
    class ClickHouseToolCallsService
      # The table's sort key, shared with ClickHouseFinder so the dedup cannot drift.
      DEDUP_COLUMNS = AuditEvents::AiAuditEvents::ClickHouseFinder::GROUP_BY_COLUMNS.join(', ').freeze

      # Shared with the tile so both count the same rows (see ToolCallsService::EVENTS for the keys).
      TOOL_NAME_SQL = "coalesce(nullIf(JSONExtractString(details, 'tool_name'), ''), " \
        "JSONExtractString(details, 'name'))"

      # ReplacingMergeTree collapses re-ingested rows only on merge, so the inner
      # query deduplicates on the sort key before counting.
      TOOL_CALLS_QUERY = <<~SQL.freeze
        SELECT
          tool_name,
          count() AS calls
        FROM (
          SELECT #{DEDUP_COLUMNS}, any(#{TOOL_NAME_SQL}) AS tool_name
          FROM ai_audit_events
          WHERE startsWith(traversal_path, {traversal_path:String})
            AND created_at >= {from:DateTime64(6, 'UTC')}
            AND created_at < {to:DateTime64(6, 'UTC')}
            AND event_name IN {events:Array(String)}
            %{agent_class_filter}
          GROUP BY #{DEDUP_COLUMNS}
        )
        WHERE tool_name != ''
        GROUP BY tool_name
        ORDER BY calls DESC, tool_name ASC
        LIMIT {limit:UInt64}
      SQL

      # Agent class lives on the workflow for events written before the move to
      # governance sessions (#630095). No lower bound on purpose: a session can
      # start long before the events it emits into the window. `deleted = false`
      # matches the PostgreSQL scope.
      WORKFLOW_AGENT_CLASS_SUBQUERY = <<~SQL
        workflow_id IN (
          SELECT id FROM (
            SELECT id,
              argMax(agent_type, _siphon_replicated_at) AS agent_type,
              argMax(_siphon_deleted, _siphon_replicated_at) AS deleted
            FROM siphon_duo_workflows_workflows
            WHERE startsWith(traversal_path, {traversal_path:String})
              AND created_at < {to:DateTime64(6, 'UTC')}
            GROUP BY traversal_path, created_at, id
          )
          WHERE deleted = false
            AND agent_type IS %{null_test}
        )
      SQL

      DUO_SOURCE = Ai::Governance::Session.sources.fetch(:gitlab_duo)

      # The namespace's sessions, deduplicated on the sort key like the events. No lower
      # bound on purpose, as for the workflows above.
      SESSIONS_SUBQUERY = <<~SQL
        SELECT id,
          argMax(source, _siphon_replicated_at) AS source,
          argMax(agent_type, _siphon_replicated_at) AS agent_type,
          argMax(_siphon_deleted, _siphon_replicated_at) AS deleted
        FROM siphon_ai_governance_sessions
        WHERE startsWith(traversal_path, {traversal_path:String})
          AND session_started_at < {to:DateTime64(6, 'UTC')}
          %{session_ids_filter}
        GROUP BY traversal_path, session_started_at, id
      SQL

      # The join reads only the sessions of the window's events, so its cost follows the
      # date range rather than the session history. An old session still matches by id.
      EVENT_SESSION_IDS_FILTER = <<~SQL
        AND id IN (
          SELECT toInt64(ai_governance_session_id) FROM ai_audit_events
          WHERE startsWith(traversal_path, {traversal_path:String})
            AND created_at >= {from:DateTime64(6, 'UTC')}
            AND created_at < {to:DateTime64(6, 'UTC')}
            AND event_name IN {events:Array(String)}
            AND ai_governance_session_id != 0
        )
      SQL

      # Duo only when it came from Duo and names no external agent; everything else
      # (glab, the Claude Compliance API, a Duo session an external agent drove) is
      # external. The sessions list splits on source alone.
      SESSION_AGENT_CLASS_SUBQUERY = <<~SQL.freeze
        ai_governance_session_id IN (
          SELECT id FROM (#{format(SESSIONS_SUBQUERY, session_ids_filter: '')})
          WHERE deleted = false
            AND %{duo_test}(source = #{DUO_SOURCE} AND coalesce(agent_type, '') = '')
        )
      SQL

      # The risk card classifies a name the GitLab CLI recorded by the agent that made the
      # call, so it reads each event's session as well. An event with no session in the
      # namespace keeps a NULL agent_type and source 0, the Duo source. The join keeps
      # deleted sessions on purpose: the call happened, so All agents still classifies it.
      # A session that moved within the group also has a tombstone under its old path, and a
      # Siphon correction tombstone holds only the key columns, so the join takes one row per
      # session and prefers the live one.
      # The limit counts tools, not rows, so every agent split of a kept tool stays and the cap
      # means the same as on the plain query.
      TOOL_CALLS_BY_AGENT_QUERY = <<~SQL.freeze
        SELECT tool_name, agent_type, source, calls
        FROM (
          SELECT *, dense_rank() OVER (ORDER BY tool_calls DESC, tool_name ASC) AS tool_rank
          FROM (
            SELECT
              events.tool_name AS tool_name,
              sessions.agent_type AS agent_type,
              sessions.source AS source,
              count() AS calls,
              sum(count()) OVER (PARTITION BY tool_name) AS tool_calls
            FROM (
              SELECT #{DEDUP_COLUMNS}, any(#{TOOL_NAME_SQL}) AS tool_name,
                toInt64(any(ai_governance_session_id)) AS session_id
              FROM ai_audit_events
              WHERE startsWith(traversal_path, {traversal_path:String})
                AND created_at >= {from:DateTime64(6, 'UTC')}
                AND created_at < {to:DateTime64(6, 'UTC')}
                AND event_name IN {events:Array(String)}
                %{agent_class_filter}
              GROUP BY #{DEDUP_COLUMNS}
            ) AS events
            LEFT JOIN (
              SELECT id, source, agent_type
              FROM (#{format(SESSIONS_SUBQUERY, session_ids_filter: EVENT_SESSION_IDS_FILTER)})
              ORDER BY id, deleted
              LIMIT 1 BY id
            ) AS sessions
              ON events.session_id = sessions.id
            WHERE tool_name != ''
            GROUP BY tool_name, agent_type, source
          )
        )
        WHERE tool_rank <= {limit:UInt64}
        ORDER BY calls DESC, tool_name ASC, agent_type ASC, source ASC
      SQL

      WORKFLOW_FILTERS = {
        internal_dap: format(WORKFLOW_AGENT_CLASS_SUBQUERY, null_test: 'NULL'),
        external: format(WORKFLOW_AGENT_CLASS_SUBQUERY, null_test: 'NOT NULL')
      }.freeze

      SESSION_FILTERS = {
        internal_dap: format(SESSION_AGENT_CLASS_SUBQUERY, duo_test: ''),
        external: format(SESSION_AGENT_CLASS_SUBQUERY, duo_test: 'NOT ')
      }.freeze

      # Fixed fragments keyed by a GraphQL enum value, never built from input.
      # The session classifies when the event has one, else the workflow, so each event lands in one segment.
      AGENT_CLASS_FILTERS = {
        internal_dap: "AND #{WORKFLOW_FILTERS[:internal_dap]}",
        # External agent sessions write events with a session ID and no workflow ID.
        external: "AND (#{WORKFLOW_FILTERS[:external]}OR (workflow_id = 0 AND ai_governance_session_id != 0))"
      }.freeze
      AGENT_CLASS_FILTERS_WITH_SESSIONS = WORKFLOW_FILTERS.to_h do |agent_class, sql|
        [agent_class, "AND ((ai_governance_session_id != 0 AND #{SESSION_FILTERS.fetch(agent_class)}) " \
          "OR (ai_governance_session_id = 0 AND #{sql}))"]
      end.freeze

      # One place picks the filter set, so the card and the tile cannot drift.
      def self.agent_class_filter(agent_class, sessions_enabled:)
        filters = sessions_enabled ? AGENT_CLASS_FILTERS_WITH_SESSIONS : AGENT_CLASS_FILTERS
        filters.fetch(agent_class, '')
      end

      def initialize(
        container, current_user:, timeframe:, agent_class: :all, sessions_enabled: false,
        by_agent: false, limit: ToolCallsService::TOP_N
      )
        @container = container
        @current_user = current_user
        @timeframe = timeframe
        @agent_class = agent_class
        @sessions_enabled = sessions_enabled
        @by_agent = by_agent
        @limit = limit
      end

      def execute
        tool_calls = select(format(query, agent_class_filter: agent_class_filter)).map do |row|
          tool_call = { tool_name: row['tool_name'], count: row['calls'].to_i }
          next tool_call unless by_agent

          tool_call.merge(agent_type: row['agent_type'], source: row['source'].to_i)
        end

        # Nothing is capped here; `approximate` only ever means a capped PostgreSQL scan.
        ServiceResponse.success(payload: { tool_calls: tool_calls, approximate: false })
      end

      private

      attr_reader :container, :current_user, :timeframe, :agent_class, :sessions_enabled, :by_agent, :limit

      def query
        by_agent ? TOOL_CALLS_BY_AGENT_QUERY : TOOL_CALLS_QUERY
      end

      def agent_class_filter
        self.class.agent_class_filter(agent_class, sessions_enabled: sessions_enabled)
      end

      def select(raw_query)
        query = ClickHouse::Client::Query.new(raw_query: raw_query, placeholders: placeholders)
        ClickHouse::Client.select(query, :main)
      end

      def placeholders
        @placeholders ||= {
          traversal_path: traversal_path,
          events: ToolCallsService::EVENTS,
          from: format_time(timeframe.from),
          to: format_time(timeframe.to),
          limit: limit
        }
      end

      def traversal_path
        namespace = container.is_a?(Project) ? container.project_namespace : container
        namespace.traversal_path(with_organization: true)
      end

      def format_time(time)
        time.utc.strftime('%Y-%m-%d %H:%M:%S.%6N')
      end
    end
  end
end
