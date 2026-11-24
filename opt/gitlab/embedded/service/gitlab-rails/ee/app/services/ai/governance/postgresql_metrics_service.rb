# frozen_string_literal: true

module Ai
  module Governance
    class PostgresqlMetricsService
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
        # Accepted for parity with the ClickHouse backend; the PostgreSQL tool calls
        # KPI follows with !256523, so nothing reads it here yet.
        @tool_calls = tool_calls
      end

      def execute
        sessions_count, sessions_previous, agents_count, agents_previous =
          windowed_scope.count_current_and_previous(
            timeframe.from, agent_excluded_references: MetricsService::AGENT_EXCLUDED_REFERENCES)

        buckets = current_window.counts_by_created_at_bucket(
          hourly: timeframe.hourly?, agent_excluded_references: MetricsService::AGENT_EXCLUDED_REFERENCES)

        payload = {
          sessions: kpi(sessions_count, sessions_previous, buckets, :sessions),
          agents: kpi(agents_count, agents_previous, buckets, :agents)
        }
        payload[:top_users] = top_activity(:user_id, top_users_limit) if top_users_limit
        payload[:top_projects] = top_activity(:project_id, top_projects_limit) if top_projects_limit
        attach_cumulative_trends(payload, buckets) if cumulative_trend

        ServiceResponse.success(payload: payload)
      end

      private

      attr_reader :container, :current_user, :timeframe, :agent_class,
        :top_users_limit, :top_projects_limit, :cumulative_trend

      # Seeds cover CUMULATIVE_LOOKBACK before the window; see Workflow.agent_first_seen_counts for the agents math.
      def attach_cumulative_trends(payload, buckets)
        sessions_baseline = base_scope.created_between(timeframe.lookback_from, timeframe.from).count
        first_seen = lookback_scope.agent_first_seen_counts(
          timeframe.from, hourly: timeframe.hourly?,
          agent_excluded_references: MetricsService::AGENT_EXCLUDED_REFERENCES)

        payload[:sessions][:cumulative_trend] =
          running_totals(sessions_baseline) { |bucket_start| buckets.dig(bucket_start, :sessions).to_i }
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

      def top_activity(column, limit)
        current_window
          .top_session_counts_by(column, limit: limit)
          .map { |value, count| { column => value, session_count: count } }
      end

      def base_scope
        scope = if container.is_a?(Project)
                  Ai::DuoWorkflows::Workflow.for_project(container)
                else
                  Ai::DuoWorkflows::Workflow.in_namespace_hierarchy(container)
                end

        scope.for_agent_class(agent_class)
      end

      # Spans both windows so one aggregate can split the totals at timeframe.from.
      def windowed_scope
        base_scope.created_between(timeframe.previous_from, timeframe.to)
      end

      def current_window
        base_scope.created_between(timeframe.from, timeframe.to)
      end

      def lookback_scope
        base_scope.created_between(timeframe.lookback_from, timeframe.to)
      end

      def kpi(count, previous_count, buckets, metric)
        {
          count: count.to_i,
          previous_count: previous_count.to_i,
          trend: zero_filled_trend(buckets, metric)
        }
      end

      def zero_filled_trend(buckets, metric)
        timeframe.bucket_starts.map do |bucket_start|
          { bucket_start: bucket_start, count: buckets.dig(bucket_start, metric).to_i }
        end
      end
    end
  end
end
