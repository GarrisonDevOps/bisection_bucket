# frozen_string_literal: true

module Ai
  module Governance
    class MetricsService
      # Agents KPI only; sessions still count every definition.
      # Version-less references, not exact definitions: rows keep the
      # workflow_definition they were written with, so matching on the
      # reference keeps historical rows (e.g. agentic_chat/v1 after a v2
      # bump) excluded without anyone maintaining a list of past versions.
      AGENT_EXCLUDED_REFERENCES = ::Ai::FoundationalChatAgent::CHAT_REFERENCES

      # Default ranking size, matching the dashboard cards' design; the GraphQL
      # `limit` argument overrides it up to its validated maximum.
      TOP_ACTIVITY_LIMIT = 5

      # The dashboard donut folds anything past its own slice count into "Other".
      SESSION_DISTRIBUTION_LIMIT = 10
      EMPTY_SESSION_DISTRIBUTION = { total_sessions: 0, total_developers: 0, slices: [] }.freeze

      # rubocop:disable Metrics/ParameterLists -- one optional keyword per selectable field, all defaulted
      def initialize(
        container, current_user:, timeframe:, agent_class: :all,
        top_users_limit: nil, top_projects_limit: nil, connected_agents_limit: nil,
        cumulative_trend: false, session_distribution: false, tool_calls: false)
        # rubocop:enable Metrics/ParameterLists
        @container = container
        @current_user = current_user
        @timeframe = MetricsTimeframe.new(timeframe)
        @agent_class = agent_class
        @top_users_limit = top_users_limit
        @top_projects_limit = top_projects_limit
        @connected_agents_limit = connected_agents_limit
        @cumulative_trend = cumulative_trend
        @session_distribution = session_distribution
        @tool_calls = tool_calls
      end

      def execute
        # agent_class filters on `agent_type`: INTERNAL_DAP => IS NULL,
        # EXTERNAL => IS NOT NULL, ALL => no filter. Nothing on master writes
        # `agent_type`, so EXTERNAL is structurally zero rather than merely small
        # until the external session API and its glab client hooks ship. The
        # predicate is still correct over an empty set, so no special-casing here.
        response = backend_class.new(
          @container,
          current_user: @current_user,
          timeframe: @timeframe,
          agent_class: @agent_class,
          top_users_limit: @top_users_limit,
          top_projects_limit: @top_projects_limit,
          cumulative_trend: @cumulative_trend,
          tool_calls: @tool_calls
        ).execute

        attach_connected_agents(response) if response.success? && @connected_agents_limit
        attach_session_distribution(response) if response.success? && @session_distribution

        response
      end

      private

      # Identities live in PostgreSQL only, so this runs regardless of the
      # analytics backend. INTERNAL_DAP has no registered machines by definition.
      def attach_connected_agents(response)
        response.payload[:connected_agents] = @agent_class == :internal_dap ? [] : connected_agents
      end

      # ClickHouse only for now; without it the distribution is empty rather than null.
      def attach_session_distribution(response)
        response.payload[:session_distribution] =
          if click_house?
            ClickHouseSessionDistributionService
              .new(@container, timeframe: @timeframe, agent_class: @agent_class, limit: SESSION_DISTRIBUTION_LIMIT)
              .execute
          else
            EMPTY_SESSION_DISTRIBUTION
          end
      end

      def connected_agents
        identities = connected_agent_identities
        registrations = identities.registration_counts_by_agent_type(limit: @connected_agents_limit)
        return [] if registrations.empty?

        activity = session_activity_by_agent_type(identities, registrations.map(&:first))

        registrations.map do |agent_type, identity_count, active_count, user_count|
          session_count, last_session_at = activity.fetch(agent_type, [0, nil])

          {
            agent_type: agent_type,
            identity_count: identity_count,
            active_count: active_count,
            revoked_count: identity_count - active_count,
            user_count: user_count,
            session_count: session_count,
            last_session_at: last_session_at
          }
        end
      end

      def session_activity_by_agent_type(identities, agent_types)
        if click_house? && Feature.enabled?(:ai_governance_sessions_api, @container.root_ancestor)
          return ClickHouseConnectedAgentActivityService
            .new(@container, timeframe: @timeframe, agent_types: agent_types)
            .execute
        end

        ::Ai::DuoWorkflows::Workflow
          .for_agent_identities(identities.with_agent_types(agent_types))
          .session_activity_by_agent_type(@timeframe.from, @timeframe.to)
      end

      def connected_agent_identities
        if @container.is_a?(::Project)
          ::Ai::ExternalAgents::AgentIdentity.for_project(@container)
        else
          ::Ai::ExternalAgents::AgentIdentity.in_namespace_hierarchy(@container)
        end
      end

      def backend_class
        click_house? ? ClickHouseMetricsService : PostgresqlMetricsService
      end

      def click_house?
        ::Gitlab::ClickHouse.enabled_for_analytics?(analytics_namespace)
      end

      def analytics_namespace
        @container.is_a?(Project) ? @container.project_namespace : @container
      end
    end
  end
end
