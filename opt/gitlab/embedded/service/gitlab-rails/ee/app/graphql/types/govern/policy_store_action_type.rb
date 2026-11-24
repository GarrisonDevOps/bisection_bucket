# frozen_string_literal: true

module Types
  module Govern
    # rubocop:disable Graphql/AuthorizeTypes -- Static catalog value object; gating happens in the resolver.
    class PolicyStoreActionType < BaseObject
      graphql_name 'PolicyStoreAction'
      description 'Action available when creating a policy in the policy store.'

      authorize_granular_token skip_reason: :parent_authorizes

      field :id, # rubocop: disable GraphQL/FieldHashKey -- BaseObject#id calls to_global_id on plain hashes; explicit override required
        GraphQL::Types::ID,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Identifier of the action.'

      field :name, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Human-readable name of the action.'

      # BaseObject#id builds a GlobalID, which these plain hash catalog entries lack.
      def id
        object[:id]
      end
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
