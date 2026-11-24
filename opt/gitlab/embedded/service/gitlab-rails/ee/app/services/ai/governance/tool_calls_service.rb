# frozen_string_literal: true

module Ai
  module Governance
    class ToolCallsService
      # Duo and glab events carry the tool in `details['tool_name']`, Claude
      # Compliance API events in `details['name']`.
      EVENTS = %w[ai_tool_invoked ai_claude_tool_invoked].freeze
      TOP_N = 10
      # Caps the distinct recorded names read before grouping; past it the counts are approximate.
      TOOL_NAME_LIMIT = 1000

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
          limit: TOOL_NAME_LIMIT + 1
        ).execute

        return response unless response.success?

        tool_calls = response.payload[:tool_calls]

        ServiceResponse.success(payload: {
          tool_calls: top_tools(tool_calls),
          approximate: response.payload[:approximate] || tool_calls.size > TOOL_NAME_LIMIT
        })
      end

      private

      # Grouped by the rule that governs each name before the cut, so a tool recorded under
      # two spellings counts once and every row names something Tool management governs.
      def top_tools(tool_calls)
        rows = tool_calls.first(TOOL_NAME_LIMIT).each_with_object({}) do |tool_call, grouped|
          resolved = names.resolve(tool_call[:tool_name])
          row = grouped[resolved[:tool_name]] ||= resolved.merge(count: 0)
          row[:count] += tool_call[:count]
        end

        rows.values.sort_by { |row| [-row[:count], row[:tool_name]] }.first(TOP_N)
      end

      def names
        @names ||= ToolCallNames.new(@container)
      end

      def clickhouse_enabled?
        ::Gitlab::ClickHouse.enabled_for_analytics?(analytics_namespace)
      end

      def analytics_namespace
        @container.is_a?(Project) ? @container.project_namespace : @container
      end
    end
  end
end
