# frozen_string_literal: true

module Types
  module Analytics
    module AiMetrics
      module AgentPlatform
        # rubocop: disable Graphql/AuthorizeTypes -- authorized by parent type
        class FlowMetricsType < BaseObject
          graphql_name 'AgentPlatformFlowMetric'
          description 'Agent platform aggregated metrics by flow type'

          field :flow_type,
            GraphQL::Types::String,
            null: false,
            description: 'Type of the flow.'

          field :sessions_count,
            GraphQL::Types::Int,
            null: false,
            description: 'Total number of sessions, equivalent to the count of the
            `agent_platform_session_created` event.'

          field :median_execution_time,
            GraphQL::Types::Float,
            null: true,
            description: 'Median flow execution time in seconds.'

          field :users_count,
            GraphQL::Types::Int,
            null: false,
            description: 'Number of unique users.'

          field :completion_rate,
            GraphQL::Types::Float,
            null: true,
            description: 'Completion rate as a percentage.'
        end
        # rubocop: enable Graphql/AuthorizeTypes
      end
    end
  end
end
