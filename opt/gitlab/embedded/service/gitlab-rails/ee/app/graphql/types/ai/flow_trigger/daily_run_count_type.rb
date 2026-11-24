# frozen_string_literal: true

module Types
  module Ai
    module FlowTrigger
      # rubocop: disable Graphql/AuthorizeTypes -- authorized by the parent AiFlowTriggerType
      class DailyRunCountType < BaseObject
        graphql_name 'AiFlowTriggerDailyRunCount'
        description 'Number of runs of a flow trigger created on one UTC day.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :date, Types::DateType,
          null: false,
          description: 'UTC day the runs were created on.'

        field :runs, GraphQL::Types::Int,
          null: false,
          description: 'Number of runs created on the day.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
