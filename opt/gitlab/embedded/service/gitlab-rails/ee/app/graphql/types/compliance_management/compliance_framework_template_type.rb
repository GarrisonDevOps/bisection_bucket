# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- Templates are static data available to any authenticated user
module Types
  module ComplianceManagement
    class ComplianceFrameworkTemplateType < ::Types::BaseObject
      graphql_name 'ComplianceFrameworkTemplate'
      description 'Represents a compliance framework template that can be used to create a compliance framework.'

      field :id, GraphQL::Types::ID,
        null: false,
        description: 'Unique identifier of the template.'

      field :template_version, GraphQL::Types::Int,
        null: false,
        description: 'Version of the template.'

      field :name, GraphQL::Types::String,
        null: false,
        description: 'Name of the compliance framework template.'

      field :description, GraphQL::Types::String,
        null: false,
        description: 'Description of the compliance framework template.'

      field :color, GraphQL::Types::String,
        null: false,
        description: "Hexadecimal representation of the template's label color."

      field :json, GraphQL::Types::String,
        null: false,
        description: 'Full JSON representation of the compliance framework template.'
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
