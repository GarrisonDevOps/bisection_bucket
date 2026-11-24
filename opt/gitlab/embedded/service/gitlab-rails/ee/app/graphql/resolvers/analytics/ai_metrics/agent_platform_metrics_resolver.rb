# frozen_string_literal: true

module Resolvers
  module Analytics
    module AiMetrics
      class AgentPlatformMetricsResolver < BaseResolver
        include LooksAhead

        type ::Types::Analytics::AiMetrics::AgentPlatformMetricsType, null: true

        # Used only by this class for negated filters
        class AgentPlatformMetricsNotInputType < ::Types::BaseInputObject
          argument :flow_types, [GraphQL::Types::String],
            required: false,
            description: 'List of flow types to exclude.'
        end

        argument :flow_types, [GraphQL::Types::String],
          required: false,
          description: 'List of flow types to filter.'

        argument :not, AgentPlatformMetricsNotInputType,
          required: false,
          description: 'Negation filters.'

        def resolve_with_lookahead(**args)
          usage = ::Analytics::AiAnalytics::AgentPlatform::EventCountService.new(
            current_user,
            namespace: context[:ai_metrics_namespace],
            from: context[:ai_metrics_params][:start_date],
            to: context[:ai_metrics_params][:end_date],
            fields: lookahead.selections.map(&:name),
            **args
          ).execute

          usage.payload
        end
      end
    end
  end
end
