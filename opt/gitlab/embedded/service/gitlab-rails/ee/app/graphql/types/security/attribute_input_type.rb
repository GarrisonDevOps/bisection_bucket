# frozen_string_literal: true

module Types
  module Security
    class AttributeInputType < BaseInputObject
      graphql_name 'SecurityAttributeInput'
      description 'Input type for security attribute'

      argument :name, GraphQL::Types::String,
        required: true,
        description: 'Name of the security attribute.'

      argument :description, GraphQL::Types::String,
        required: true,
        description: 'Description of the security attribute.'

      argument :color, Types::ColorType,
        required: true,
        description: 'Color of the security attribute.'
    end
  end
end
