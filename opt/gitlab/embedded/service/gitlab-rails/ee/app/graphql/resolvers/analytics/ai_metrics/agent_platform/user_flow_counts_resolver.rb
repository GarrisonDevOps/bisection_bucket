# frozen_string_literal: true

module Resolvers
  module Analytics
    module AiMetrics
      module AgentPlatform
        class UserFlowCountsResolver < BaseResolver
          include LooksAhead

          type ::Types::Analytics::AiMetrics::AgentPlatform::UserFlowCountType.connection_type, null: true

          def resolve_with_lookahead
            flow_metrics = ::Analytics::AiAnalytics::AgentPlatform::UserFlowCountService.new(
              current_user,
              namespace: context[:ai_metrics_namespace],
              from: context[:ai_metrics_params][:start_date],
              to: context[:ai_metrics_params][:end_date]
            ).execute

            flow_metrics.payload
          end
        end
      end
    end
  end
end
