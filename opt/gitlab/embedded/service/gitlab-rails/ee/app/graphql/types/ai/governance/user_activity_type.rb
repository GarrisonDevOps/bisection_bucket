# frozen_string_literal: true

module Types
  module Ai
    module Governance
      # Reachable only through fields that already authorize against the
      # group or project, so no object-level authorization is needed here.
      class UserActivityType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'AiGovernanceUserActivity'
        description 'AI session activity of a single user.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :session_count, GraphQL::Types::Int, null: true,
          description: 'Number of AI sessions the user started in the selected timeframe.'
        field :user, Types::UserType, null: true,
          description: 'User the sessions belong to.'

        def user
          Gitlab::Graphql::Loaders::BatchModelLoader.new(User, object[:user_id]).find
        end
      end
    end
  end
end
