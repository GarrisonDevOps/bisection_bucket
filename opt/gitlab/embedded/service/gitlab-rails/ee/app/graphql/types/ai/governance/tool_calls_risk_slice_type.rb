# frozen_string_literal: true

module Types
  module Ai
    module Governance
      # Reachable only through fields that already authorize against the
      # group or project, so no object-level authorization is needed here.
      class ToolCallsRiskSliceType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'AiGovernanceToolCallsRiskSlice'
        description 'Number of AI agent tool calls at one risk level.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :count, GraphQL::Types::Int, null: false,
          description: 'Number of tool invocations at the risk level in the selected timeframe.'
        field :risk, ::Types::Ai::Governance::ToolRiskEnum, null: false,
          description: 'Risk level of the tools.'
      end
    end
  end
end
