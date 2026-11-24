# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class SchemaNodeType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitSchemaNode'
        description 'Node kind in the Orbit schema.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :description, GraphQL::Types::String, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Description of the node kind.'
        field :display, SchemaDisplayType, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          hash_key: :style,
          description: 'How to draw nodes of the kind.'
        field :domain, SchemaDomainType, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Domain of the node kind.'
        field :label_property, GraphQL::Types::String, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          hash_key: :label_field,
          description: 'Property to show as the label of a node.'
        field :name, GraphQL::Types::String, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Name of the node kind. Queries use it as the node label.'
        field :primary_key, GraphQL::Types::String, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Property that identifies a node.'
        field :properties, SchemaPropertyType.connection_type, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Properties of the node kind.'

        def domain
          { name: object[:domain] }
        end

        def properties
          object.fetch(:properties, [])
        end
      end
    end
  end
end
