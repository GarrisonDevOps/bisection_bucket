# frozen_string_literal: true

module Types
  module Ai
    module Governance
      # Reachable only through fields that already authorize against the
      # group or project, so no object-level authorization is needed here.
      class SessionDistributionSliceType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'AiGovernanceSessionDistributionSlice'
        description 'AI sessions and developers for one agent or flow type.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :developers, GraphQL::Types::Int, null: false,
          description: 'Number of distinct developers with sessions in the slice.'
        field :name, GraphQL::Types::String, null: false,
          description: 'Name of the slice. Version-less flow type for `INTERNAL_DAP`, agent type for ' \
            "`EXTERNAL`. For `ALL`, `#{::Ai::Governance::ClickHouseSessionDistributionService::DUO_NAME}` " \
            'for GitLab Duo sessions and agent type for external sessions.'
        field :sessions, GraphQL::Types::Int, null: false,
          description: 'Number of sessions in the slice.'
      end
    end
  end
end
