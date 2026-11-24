# frozen_string_literal: true

module Types
  module Ai
    module Governance
      # Reachable only through fields that already authorize against the
      # group or project, so no object-level authorization is needed here.
      class ToolCallsByRiskType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'AiGovernanceToolCallsByRisk'
        description 'AI agent tool calls grouped by risk level.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :approximate, GraphQL::Types::Boolean, null: false,
          description: 'Whether the counts leave out some tools because the namespace used more distinct ' \
            'tools than are read.'
        field :slices, [::Types::Ai::Governance::ToolCallsRiskSliceType], null: false,
          description: 'Tool calls per risk level, in the order READ, WRITE, DESTROY, UNCLASSIFIED. ' \
            'Risk levels with no calls have a count of zero.'
        field :total, GraphQL::Types::Int, null: false,
          description: 'Total number of tool invocations in the selected timeframe.'
      end
    end
  end
end
