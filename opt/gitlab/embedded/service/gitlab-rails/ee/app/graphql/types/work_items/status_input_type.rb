# frozen_string_literal: true

module Types
  module WorkItems
    class StatusInputType < BaseInputObject
      graphql_name 'WorkItemStatusInput'

      argument :id, ::Types::GlobalIDType,
        required: false,
        description: 'ID of the status. If not provided, a new status will be created.'

      argument :name, GraphQL::Types::String,
        required: false,
        description: 'Name of the status.'

      argument :color, GraphQL::Types::String,
        required: false,
        description: 'Color of the status.'

      argument :description, GraphQL::Types::String,
        required: false,
        description: 'Description of the status.'

      argument :category, Types::WorkItems::StatusCategoryEnum,
        required: false,
        description: 'Category of the status.'
    end
  end
end
