# frozen_string_literal: true

module Types
  module Analytics
    module Dashboards
      class VisualizationType < BaseObject
        graphql_name 'CustomizableDashboardVisualization'
        description 'Represents a customizable dashboard visualization.'
        authorize :read_customizable_dashboards

        field :type,
          type: GraphQL::Types::String,
          null: false,
          description: 'Type of the visualization.'

        field :options,
          type: GraphQL::Types::JSON,
          null: false,
          description: 'Options of the visualization.'

        field :data,
          type: GraphQL::Types::JSON,
          null: false,
          description: 'Data of the visualization.'

        field :slug,
          type: GraphQL::Types::String,
          null: false,
          description: 'Slug of the visualization.'

        field :errors,
          type: [GraphQL::Types::String],
          null: true,
          description: 'Validation errors in the visualization.'
      end
    end
  end
end
