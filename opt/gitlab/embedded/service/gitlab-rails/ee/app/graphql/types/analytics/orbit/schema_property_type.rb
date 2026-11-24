# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class SchemaPropertyType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'OrbitSchemaProperty'
        description 'Property of a node kind in the Orbit schema.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :data_type, GraphQL::Types::String, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Data type of the property, for example `string` or `int64`.'
        field :default_column, GraphQL::Types::Boolean, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Indicates whether Orbit returns the property in neighbor and path results, ' \
            'and when a query selects no properties. Null when the Orbit server does not send it.'
        field :enum_values, [GraphQL::Types::String], null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Allowed values of an enum property. Empty for other properties.'
        field :name, GraphQL::Types::String, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Name of the property.'
        field :nullable, GraphQL::Types::Boolean, null: false,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Indicates whether the property can be empty.'
        field :text_searchable, GraphQL::Types::Boolean, null: true,
          scopes: AI_WORKFLOW_SCOPES,
          description: 'Indicates whether queries can filter the property with `CONTAINS`, `STARTS WITH`, ' \
            'or `ENDS WITH`. Null when the Orbit server does not send it.'
      end
    end
  end
end
