# frozen_string_literal: true

module Types
  module Govern
    # rubocop:disable Graphql/AuthorizeTypes -- Static catalog value object; gating happens in the parent resolver.
    class PolicyStoreRoleType < BaseObject
      graphql_name 'PolicyStoreRole'
      description 'A role that can be assigned in a policy action'

      authorize_granular_token skip_reason: :parent_authorizes

      field :id, # rubocop: disable GraphQL/FieldHashKey -- BaseObject#id calls to_global_id on plain hashes; explicit override required
        GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Unique identifier for the role.'

      field :name, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Human-readable name of the role.'

      # BaseObject#id builds a GlobalID, which these plain hash catalog entries lack.
      def id
        object[:id]
      end
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
