# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class ItemTypeCountType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitItemTypeCount'
        description 'Number of indexed items of one Orbit item type.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :count, GraphQL::Types::BigInt, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Number of indexed items of the item type.'
        field :name, GraphQL::Types::String, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Name of the item type.'
      end
    end
  end
end
