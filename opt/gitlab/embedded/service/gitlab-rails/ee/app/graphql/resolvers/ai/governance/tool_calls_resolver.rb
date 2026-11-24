# frozen_string_literal: true

module Resolvers
  module Ai
    module Governance
      class ToolCallsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        type ::Types::Ai::Governance::ToolCallsReportType, null: true

        authorize :read_agent_artifacts
        authorizes_object!

        argument :timeframe, ::Types::Ai::Governance::MetricsTimeframeEnum,
          required: false,
          default_value: :last_7_days,
          description: 'Time window for the tool calls. Defaults to LAST_7_DAYS.'

        argument :agent_class, ::Types::Ai::Governance::AgentClassEnum,
          required: false,
          default_value: :all,
          description: 'Agent class to segment the tool calls by. Defaults to ALL.'

        extras [:lookahead]

        def resolve(timeframe:, agent_class:, lookahead:)
          return unless Feature.enabled?(:ai_governance_dashboard, object.root_ancestor)
          return unless Feature.enabled?(:ai_governance_tool_calls, object.root_ancestor)

          args = { current_user: current_user, timeframe: timeframe, agent_class: agent_class }
          report = {}

          if top_tools_selected?(lookahead)
            response = ::Ai::Governance::ToolCallsService.new(object, **args).execute
            return unless response.success?

            report.merge!(nodes: response.payload[:tool_calls], approximate: response.payload[:approximate])
          end

          if lookahead.selects?(:by_risk)
            response = ::Ai::Governance::ToolCallsByRiskService.new(object, **args).execute
            return unless response.success?

            report[:by_risk] = response.payload
          end

          report
        end

        private

        def top_tools_selected?(lookahead)
          lookahead.selects?(:nodes) || lookahead.selects?(:approximate)
        end
      end
    end
  end
end
