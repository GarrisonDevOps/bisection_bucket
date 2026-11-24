# frozen_string_literal: true

module Types
  module Ai
    module Governance
      # Reachable only through fields that already authorize against the
      # group or project, so no object-level authorization is needed here.
      class ToolCallsReportType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'AiGovernanceToolCallsReport'
        description 'Top tools invoked by AI agents, with a flag marking approximate counts.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :approximate, GraphQL::Types::Boolean, null: false,
          description: 'Indicates whether counts were capped and are approximate.'
        field :by_risk, ::Types::Ai::Governance::ToolCallsByRiskType, null: true,
          description: 'Tool calls grouped by risk level. Computed only when selected.',
          experiment: { milestone: '19.5' }
        field :nodes, [::Types::Ai::Governance::ToolCallType], null: false,
          description: 'Tools invoked in the selected timeframe, ordered by invocation count.'
      end
    end
  end
end
