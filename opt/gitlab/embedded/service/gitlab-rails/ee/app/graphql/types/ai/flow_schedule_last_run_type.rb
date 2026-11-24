# frozen_string_literal: true

module Types
  module Ai
    # rubocop: disable Graphql/AuthorizeTypes -- authorized by the parent AiFlowScheduleType
    class FlowScheduleLastRunType < BaseObject
      graphql_name 'AiFlowScheduleLastRun'
      description 'Details of the most recent execution attempt of a flow schedule.'

      authorize_granular_token skip_reason: :parent_authorizes

      field :ran_at, Types::TimeType,
        null: true,
        method: :last_run_at,
        description: 'Timestamp of the most recent execution attempt.'

      field :status, GraphQL::Types::String,
        null: true,
        method: :last_run_status,
        description: 'Status of the most recent execution attempt.'

      field :error, GraphQL::Types::String,
        null: true,
        method: :last_run_error,
        description: 'Error message from the most recent failed execution.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
