# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class SchemaEdgeType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitSchemaEdge'
        description 'Edge kind in the Orbit schema.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :description, GraphQL::Types::String, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Description of the edge kind.'
        field :endpoints, SchemaEdgeEndpointType.connection_type, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Pairs of node kinds that the edge kind connects.'
        field :name, GraphQL::Types::String, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Name of the edge kind. Queries use it as the relationship type.'
      end
    end
  end
end
