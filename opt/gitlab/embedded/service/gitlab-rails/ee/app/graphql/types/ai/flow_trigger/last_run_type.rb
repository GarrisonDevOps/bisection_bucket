# frozen_string_literal: true

module Types
  module Ai
    module FlowTrigger
      # rubocop: disable Graphql/AuthorizeTypes -- authorized by the parent AiFlowTriggerType
      class LastRunType < BaseObject
        graphql_name 'AiFlowTriggerLastRun'
        description 'Details of the most recent run of a flow trigger.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :status, Types::Ai::FlowTrigger::RunStatusEnum,
          null: false,
          description: 'Status of the run.'

        field :started_at, Types::TimeType,
          null: false,
          description: 'Timestamp of when the run started.'

        field :finished_at, Types::TimeType,
          null: true,
          description: 'Timestamp of when the run finished, or null if the run is not finished.'

        field :error, GraphQL::Types::String,
          null: true,
          description: 'Error message of a scheduled run that failed before a session started.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
