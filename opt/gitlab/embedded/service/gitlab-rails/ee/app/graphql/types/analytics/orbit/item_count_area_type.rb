# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class ItemCountAreaType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitItemCountArea'
        description 'Number of indexed items in one Orbit area.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :item_types, [ItemTypeCountType], null: true,
          scopes: AI_WORKFLOW_SCOPES,
          hash_key: :entities,
          description: 'Number of indexed items of each item type in the area.'
        field :name, GraphQL::Types::String, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Name of the area.'
      end
    end
  end
end
