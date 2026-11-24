# frozen_string_literal: true

module Ai
  module Governance
    class ToolCallsByRiskService
      RISKS = %i[read write destroy unclassified].freeze
      TOOL_NAME_LIMIT = ToolCallsService::TOOL_NAME_LIMIT
      GLAB_SOURCE = Ai::Governance::Session.sources.fetch(:claude_code_glab)

      def initialize(container, current_user:, timeframe:, agent_class: :all)
        @container = container
        @current_user = current_user
        @timeframe = MetricsTimeframe.new(timeframe)
        @agent_class = agent_class
      end

      def execute
        return ServiceResponse.error(message: 'ClickHouse is not enabled for analytics') unless clickhouse_enabled?

        response = ClickHouseToolCallsService.new(
          @container,
          current_user: @current_user,
          timeframe: @timeframe,
          agent_class: @agent_class,
          sessions_enabled: Feature.enabled?(:ai_governance_sessions_api, @container.root_ancestor),
          by_agent: true,
          limit: TOOL_NAME_LIMIT + 1
        ).execute

        return response unless response.success?

        ServiceResponse.success(payload: by_risk(response.payload[:tool_calls]))
      end

      private

      # Rows are split by agent, so the cap counts tools: the query returns up to one more tool
      # than the cap, with every split of each, and the busiest tools are kept.
      def by_risk(tool_calls)
        counts = RISKS.index_with(0)
        totals = tool_calls.each_with_object(Hash.new(0)) { |row, sums| sums[row[:tool_name]] += row[:count] }
        kept = totals.sort_by { |name, count| [-count, name] }.first(TOOL_NAME_LIMIT).to_set(&:first)

        tool_calls.each do |tool_call|
          counts[risk_of(tool_call)] += tool_call[:count] if kept.include?(tool_call[:tool_name])
        end

        {
          total: counts.values.sum,
          slices: RISKS.map { |risk| { risk: risk, count: counts[risk] } },
          approximate: totals.size > TOOL_NAME_LIMIT
        }
      end

      # A session the GitLab CLI uploaded names its agent, and only the reviewed list for
      # that agent says what its tools do. Everything else is classified exactly as the
      # Top tools card badges each row, so the two cannot disagree. Compliance API sessions
      # name an agent too, but their tool names are not verified yet, so they keep that lookup.
      def risk_of(tool_call)
        action_type =
          if tool_call[:source] == GLAB_SOURCE
            ExternalAgentTools.action_type_of(tool_call[:agent_type], tool_call[:tool_name])
          else
            names.resolve(tool_call[:tool_name])[:action_type]
          end

        action_type || :unclassified
      end

      def names
        @names ||= ToolCallNames.new(@container)
      end

      def clickhouse_enabled?
        ::Gitlab::ClickHouse.enabled_for_analytics?(namespace)
      end

      def namespace
        @container.is_a?(Project) ? @container.project_namespace : @container
      end
    end
  end
end
