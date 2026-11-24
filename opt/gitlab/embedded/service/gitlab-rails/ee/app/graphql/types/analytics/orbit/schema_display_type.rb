# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class SchemaDisplayType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitSchemaDisplay'
        description 'How to draw nodes of a kind in the Orbit schema.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :color, GraphQL::Types::String, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Hex color of the node kind.'
        field :size, GraphQL::Types::Int, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Relative size of the node kind in a graph.'
      end
    end
  end
end
