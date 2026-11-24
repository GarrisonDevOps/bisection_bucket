# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class SchemaEdgeEndpointType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitSchemaEdgeEndpoint'
        description 'Pair of node kinds that an edge kind connects.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :source, SchemaNodeType, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Node kind at the start of the edge.'
        field :target, SchemaNodeType, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Node kind at the end of the edge.'
      end
    end
  end
end
