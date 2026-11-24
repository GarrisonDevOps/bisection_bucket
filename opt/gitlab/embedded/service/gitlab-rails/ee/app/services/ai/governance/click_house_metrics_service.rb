# frozen_string_literal: true

module Ai
  module Governance
    class ClickHouseMetricsService
      include Gitlab::Utils::StrongMemoize

      # Mirrors Ai::DuoWorkflows::Workflow::AGENT_INSTANCE_KEY. Internal DAP sessions key
      # on (user, container, normalized environment), where the container is both
      # project_id and namespace_id, external ones on
      # (user, project, agent_type, agent_identity_id), discriminated by agent_type
      # being NULL. agent_identity_id is siphoned, so both paths agree.
      #
      # The environment mapping is derived from the same model constants the PostgreSQL
      # key uses, so the two cannot drift. `transform` passes NULL through unchanged.
      NORMALIZED_ENVIRONMENT =
        begin
          environments = ::Ai::DuoWorkflows::Workflow.environments
          renamed_from, renamed_to = ::Ai::DuoWorkflows::Workflow::ENVIRONMENTS_DEPRECATIONS
            .map { |from, to| [environments.fetch(from), environments.fetch(to)] }
            .transpose

          "transform(environment, [#{renamed_from.join(', ')}], [#{renamed_to.join(', ')}], environment)".freeze
        end

      AGENT_INSTANCE_KEY =
        "(#{::Ai::DuoWorkflows::Workflow::AGENT_INSTANCE_KEY_COLUMNS.join(', ')}, " \
          "if(agent_type IS NULL, #{NORMALIZED_ENVIRONMENT}, NULL))".freeze

      # Sessions count every definition; the exclusion applies to the agents
      # aggregates only (chat conversations are not agent instances).
      TOTALS_QUERY = <<~SQL.freeze
        SELECT
          countIf(created_at >= {from:DateTime64(6, 'UTC')}) AS sessions_count,
          countIf(created_at < {from:DateTime64(6, 'UTC')}) AS sessions_previous_count,
          uniqExactIf(#{AGENT_INSTANCE_KEY}, created_at >= {from:DateTime64(6, 'UTC')}
            AND splitByChar('/', workflow_definition)[1] NOT IN {agent_excluded_references:Array(String)}) AS agents_count,
          uniqExactIf(#{AGENT_INSTANCE_KEY}, created_at < {from:DateTime64(6, 'UTC')}
            AND splitByChar('/', workflow_definition)[1] NOT IN {agent_excluded_references:Array(String)}) AS agents_previous_count
        FROM (%{dedup_subquery})
        WHERE deleted = false
          %{agent_class_filter}
      SQL

      TREND_QUERY = <<~SQL.freeze
        SELECT
          toStartOfInterval(created_at, INTERVAL 1 %{unit}) AS bucket_start,
          count() AS sessions_count,
          uniqExactIf(#{AGENT_INSTANCE_KEY},
            splitByChar('/', workflow_definition)[1] NOT IN {agent_excluded_references:Array(String)}) AS agents_count
        FROM (%{dedup_subquery})
        WHERE deleted = false
          AND created_at >= {from:DateTime64(6, 'UTC')}
          %{agent_class_filter}
        GROUP BY bucket_start
        ORDER BY bucket_start ASC
      SQL

      # Rankings share the sessions population (every definition, chat included);
      # project_id IS NOT NULL only bites for the project dimension, where
      # namespace-attached sessions have no project to attribute to.
      TOP_ACTIVITY_QUERY = <<~SQL
        SELECT %{dimension}, count() AS session_count
        FROM (%{dedup_subquery})
        WHERE deleted = false
          AND created_at >= {from:DateTime64(6, 'UTC')}
          AND %{dimension} IS NOT NULL
          %{agent_class_filter}
        GROUP BY %{dimension}
        ORDER BY session_count DESC, %{dimension} ASC
        LIMIT {top_activity_limit:UInt8}
      SQL

      SESSIONS_BASELINE_QUERY = <<~SQL
        SELECT count() AS sessions_baseline
        FROM (%{dedup_subquery})
        WHERE deleted = false
          AND created_at < {from:DateTime64(6, 'UTC')}
          %{agent_class_filter}
      SQL

      # Same shape as Workflow.agent_first_seen_counts; see it for the running-sum reasoning.
      AGENT_FIRST_SEEN_QUERY = <<~SQL.freeze
        SELECT
          CASE WHEN first_seen >= {from:DateTime64(6, 'UTC')}
            THEN toStartOfInterval(first_seen, INTERVAL 1 %{unit}) END AS bucket_start,
          count() AS new_agents
        FROM (
          SELECT min(created_at) AS first_seen
          FROM (%{dedup_subquery})
          WHERE deleted = false
            AND splitByChar('/', workflow_definition)[1] NOT IN {agent_excluded_references:Array(String)}
            %{agent_class_filter}
          GROUP BY #{AGENT_INSTANCE_KEY}
        )
        GROUP BY bucket_start
      SQL

      # Tool calls come from ai_audit_events, so they get their own pass rather
      # than riding along with the session aggregates. The inner query dedups
      # on the sort key and drops invocations without a tool name, so the tile
      # and the "Top tools" card count the same events.
      TOOL_CALLS_DEDUP_QUERY = <<~SQL.freeze
        SELECT #{ClickHouseToolCallsService::DEDUP_COLUMNS}, any(#{ClickHouseToolCallsService::TOOL_NAME_SQL}) AS tool_name
        FROM ai_audit_events
        WHERE startsWith(traversal_path, {traversal_path:String})
          AND created_at >= {%{lower_bound}:DateTime64(6, 'UTC')}
          AND created_at < {%{upper_bound}:DateTime64(6, 'UTC')}
          AND event_name IN {tool_call_events:Array(String)}
          %{agent_class_filter}
        GROUP BY #{ClickHouseToolCallsService::DEDUP_COLUMNS}
      SQL

      TOOL_CALLS_TOTALS_QUERY = <<~SQL
        SELECT
          countIf(created_at >= {from:DateTime64(6, 'UTC')}) AS tool_calls_count,
          countIf(created_at < {from:DateTime64(6, 'UTC')}) AS tool_calls_previous_count
        FROM (%{dedup})
        WHERE tool_name != ''
      SQL

      TOOL_CALLS_TREND_QUERY = <<~SQL
        SELECT
          toStartOfInterval(created_at, INTERVAL 1 %{unit}) AS bucket_start,
          count() AS tool_calls_count
        FROM (%{dedup})
        WHERE tool_name != ''
        GROUP BY bucket_start
        ORDER BY bucket_start ASC
      SQL

      TOOL_CALLS_BASELINE_QUERY = <<~SQL
        SELECT count() AS tool_calls_baseline
        FROM (%{dedup})
        WHERE tool_name != ''
      SQL

      DEDUP_SUBQUERY = <<~SQL
        SELECT
          id,
          created_at,
          argMax(workflow_definition, _siphon_replicated_at) AS workflow_definition,
          argMax(user_id, _siphon_replicated_at) AS user_id,
          argMax(project_id, _siphon_replicated_at) AS project_id,
          argMax(namespace_id, _siphon_replicated_at) AS namespace_id,
          argMax(environment, _siphon_replicated_at) AS environment,
          argMax(agent_type, _siphon_replicated_at) AS agent_type,
          argMax(agent_identity_id, _siphon_replicated_at) AS agent_identity_id,
          argMax(_siphon_deleted, _siphon_replicated_at) AS deleted
        FROM siphon_duo_workflows_workflows
        WHERE startsWith(traversal_path, {traversal_path:String})
          %{lower_bound}
          AND created_at < {to:DateTime64(6, 'UTC')}
        GROUP BY traversal_path, created_at, id
      SQL

      # siphon_ai_governance_sessions in the DEDUP_SUBQUERY shape, so every query above
      # reads it unchanged: session_started_at is the time dimension and flow_type stands in
      # for workflow_definition. `source` stays exposed for the agent class filter.
      SESSIONS_DEDUP_SUBQUERY = <<~SQL
        SELECT
          id,
          session_started_at AS created_at,
          ifNull(argMax(flow_type, _siphon_replicated_at), '') AS workflow_definition,
          argMax(user_id, _siphon_replicated_at) AS user_id,
          argMax(project_id, _siphon_replicated_at) AS project_id,
          argMax(namespace_id, _siphon_replicated_at) AS namespace_id,
          CAST(NULL AS Nullable(Int16)) AS environment,
          argMax(agent_type, _siphon_replicated_at) AS agent_type,
          argMax(agent_identity_id, _siphon_replicated_at) AS agent_identity_id,
          argMax(_siphon_deleted, _siphon_replicated_at) AS deleted,
          argMax(source, _siphon_replicated_at) AS source
        FROM siphon_ai_governance_sessions
        WHERE startsWith(traversal_path, {traversal_path:String})
          %{lower_bound}
          AND session_started_at < {to:DateTime64(6, 'UTC')}
        GROUP BY traversal_path, session_started_at, id
      SQL

      # agent_class => SQL fragment on the deduplicated `agent_type` column.
      # Values come from a GraphQL enum, so these are fixed, non-interpolated
      # fragments (no injection surface).
      AGENT_CLASS_FILTERS = {
        internal_dap: 'AND agent_type IS NULL',
        external: 'AND agent_type IS NOT NULL'
      }.freeze

      # Same split as the agents card: a Duo-run session that names an external agent is External.
      SESSIONS_AGENT_CLASS_FILTERS = {
        internal_dap: "AND #{ClickHouseSessionDistributionService::DUO_CONDITION}",
        external: "AND NOT #{ClickHouseSessionDistributionService::DUO_CONDITION}"
      }.freeze

      def initialize(
        container, current_user:, timeframe:, agent_class: :all,
        top_users_limit: nil, top_projects_limit: nil, cumulative_trend: false, tool_calls: false)
        @container = container
        @current_user = current_user
        @timeframe = timeframe
        @agent_class = agent_class
        @top_users_limit = top_users_limit
        @top_projects_limit = top_projects_limit
        @cumulative_trend = cumulative_trend
        @tool_calls = tool_calls
      end

      def execute
        totals = select(format(TOTALS_QUERY, dedup_subquery: dedup_subquery,
          agent_class_filter: agent_class_filter)).first || {}
        trend_rows = select(format(TREND_QUERY, dedup_subquery: dedup_subquery,
          unit: interval_unit, agent_class_filter: agent_class_filter))

        payload = {
          sessions: kpi(totals, trend_rows, 'sessions_count'),
          agents: kpi(totals, trend_rows, 'agents_count')
        }
        payload[:top_users] = top_activity('user_id', :user_id, top_users_limit) if top_users_limit
        payload[:top_projects] = top_activity('project_id', :project_id, top_projects_limit) if top_projects_limit
        payload[:tool_calls] = tool_calls_kpi if tool_calls
        attach_cumulative_trends(payload) if cumulative_trend

        ServiceResponse.success(payload: payload)
      end

      private

      attr_reader :container, :current_user, :timeframe, :agent_class,
        :top_users_limit, :top_projects_limit, :cumulative_trend, :tool_calls

      def attach_cumulative_trends(payload)
        sessions_baseline = select(format(SESSIONS_BASELINE_QUERY,
          dedup_subquery: dedup_subquery(lower_bound: :lookback_from),
          agent_class_filter: agent_class_filter)).first&.fetch('sessions_baseline').to_i
        first_seen_rows = select(format(AGENT_FIRST_SEEN_QUERY,
          dedup_subquery: dedup_subquery(lower_bound: :lookback_from),
          unit: interval_unit, agent_class_filter: agent_class_filter))
        first_seen = first_seen_rows.to_h do |row|
          [row['bucket_start'] && parse_bucket(row['bucket_start']), row['new_agents'].to_i]
        end

        sessions_counts = payload[:sessions][:trend].to_h { |point| [point[:bucket_start], point[:count]] }
        payload[:sessions][:cumulative_trend] =
          running_totals(sessions_baseline) { |bucket_start| sessions_counts.fetch(bucket_start, 0) }
        payload[:agents][:cumulative_trend] =
          running_totals(first_seen[nil].to_i) { |bucket_start| first_seen.fetch(bucket_start, 0) }
      end

      def running_totals(baseline)
        running = baseline
        timeframe.bucket_starts.map do |bucket_start|
          running += yield(bucket_start)
          { bucket_start: bucket_start, count: running }
        end
      end

      def tool_calls_kpi
        totals = select(format(TOOL_CALLS_TOTALS_QUERY,
          dedup: tool_calls_dedup_query(:previous_from, :to))).first || {}
        trend_rows = select(format(TOOL_CALLS_TREND_QUERY,
          unit: interval_unit, dedup: tool_calls_dedup_query(:from, :to)))
        kpi = kpi(totals, trend_rows, 'tool_calls_count')
        kpi[:cumulative_trend] = tool_calls_cumulative_trend(kpi[:trend]) if cumulative_trend

        kpi
      end

      # Invocations are plain row counts, so the running total seeds from the
      # count before the window, the same way sessions does.
      def tool_calls_cumulative_trend(trend)
        baseline = select(format(TOOL_CALLS_BASELINE_QUERY,
          dedup: tool_calls_dedup_query(:lookback_from, :from))).first.to_h['tool_calls_baseline'].to_i
        counts = trend.to_h { |point| [point[:bucket_start], point[:count]] }

        running_totals(baseline) { |bucket_start| counts.fetch(bucket_start, 0) }
      end

      def tool_calls_dedup_query(lower_bound, upper_bound)
        format(TOOL_CALLS_DEDUP_QUERY, lower_bound: lower_bound, upper_bound: upper_bound,
          agent_class_filter: tool_calls_agent_class_filter)
      end

      # Every variant keeps a lower bound so cost does not grow with a hierarchy's history.
      def dedup_subquery(lower_bound: :previous_from)
        bound = "{#{lower_bound}:DateTime64(6, 'UTC')}"

        if governance_sessions?
          format(SESSIONS_DEDUP_SUBQUERY, lower_bound: "AND session_started_at >= #{bound}")
        else
          format(DEDUP_SUBQUERY, lower_bound: "AND created_at >= #{bound}")
        end
      end

      # Flag on: every agent class reads siphon_ai_governance_sessions; off: the workflows table.
      def governance_sessions?
        Feature.enabled?(:ai_governance_sessions_api, container.root_ancestor)
      end
      strong_memoize_attr :governance_sessions?

      def top_activity(dimension, id_key, limit)
        raw_query = format(TOP_ACTIVITY_QUERY, dedup_subquery: dedup_subquery,
          dimension: dimension, agent_class_filter: agent_class_filter)
        query = ClickHouse::Client::Query.new(raw_query: raw_query,
          placeholders: placeholders.merge(top_activity_limit: limit))
        rows = ClickHouse::Client.select(query, :main)

        rows.map { |row| { id_key => row[dimension].to_i, session_count: row['session_count'].to_i } }
      end

      def agent_class_filter
        filters = governance_sessions? ? SESSIONS_AGENT_CLASS_FILTERS : AGENT_CLASS_FILTERS
        filters.fetch(agent_class, '')
      end

      def tool_calls_agent_class_filter
        # The tool calls reader picks the filter set, so the card and the tile cannot drift.
        ::Ai::Governance::ClickHouseToolCallsService
          .agent_class_filter(agent_class, sessions_enabled: governance_sessions?)
      end

      def kpi(totals, trend_rows, count_key)
        counts = trend_rows.to_h { |row| [parse_bucket(row['bucket_start']), row[count_key].to_i] }

        {
          count: totals[count_key].to_i,
          previous_count: totals["#{count_key.delete_suffix('_count')}_previous_count"].to_i,
          trend: timeframe.bucket_starts.map do |bucket_start|
            { bucket_start: bucket_start, count: counts.fetch(bucket_start, 0) }
          end
        }
      end

      def select(raw_query)
        query = ClickHouse::Client::Query.new(raw_query: raw_query, placeholders: placeholders)
        ClickHouse::Client.select(query, :main)
      end

      def placeholders
        @placeholders ||= {
          traversal_path: traversal_path,
          agent_excluded_references: MetricsService::AGENT_EXCLUDED_REFERENCES,
          tool_call_events: ToolCallsService::EVENTS,
          from: format_time(timeframe.from),
          previous_from: format_time(timeframe.previous_from),
          lookback_from: format_time(timeframe.lookback_from),
          to: format_time(timeframe.to)
        }
      end

      def traversal_path
        namespace = container.is_a?(Project) ? container.project_namespace : container
        namespace.traversal_path(with_organization: true)
      end

      def interval_unit
        timeframe.hourly? ? 'hour' : 'day'
      end

      def format_time(time)
        time.utc.strftime('%Y-%m-%d %H:%M:%S.%6N')
      end

      def parse_bucket(value)
        value.is_a?(String) ? Time.parse("#{value} UTC").utc : value.to_time.utc
      end
    end
  end
end
