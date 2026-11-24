# frozen_string_literal: true

module Types
  module Ai
    module FlowTrigger
      # rubocop: disable Graphql/AuthorizeTypes -- authorized by the parent AiFlowTriggerType
      class RunStatsType < BaseObject
        graphql_name 'AiFlowTriggerRunStats'
        description 'Statistics of the runs of a flow trigger created in the last 30 days.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :total_runs, GraphQL::Types::Int,
          null: false,
          description: 'Number of runs.'

        field :finished_runs, GraphQL::Types::Int,
          null: false,
          description: 'Number of runs that finished successfully.'

        field :failed_runs, GraphQL::Types::Int,
          null: false,
          description: 'Number of runs that failed.'

        field :stopped_runs, GraphQL::Types::Int,
          null: false,
          description: 'Number of runs that were stopped.'

        field :median_duration_seconds, GraphQL::Types::Float,
          null: true,
          description: 'Median time in seconds from creation to last update of runs that finished, failed, ' \
            'or were stopped. Null if no run has ended.'

        field :daily_volume, [Types::Ai::FlowTrigger::DailyRunCountType],
          null: false,
          description: 'Number of runs created on each UTC day. Days without runs are omitted.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
