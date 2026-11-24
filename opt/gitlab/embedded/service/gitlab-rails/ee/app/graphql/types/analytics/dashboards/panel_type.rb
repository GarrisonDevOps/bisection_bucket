# frozen_string_literal: true

module Types
  module Analytics
    module Dashboards
      class PanelType < BaseObject
        graphql_name 'CustomizableDashboardPanel'
        description 'Represents a customizable dashboard panel.'
        authorize :read_customizable_dashboards

        field :title,
          type: GraphQL::Types::String,
          null: true,
          description: 'Title of the panel.'

        field :title_icon,
          type: GraphQL::Types::String,
          null: true,
          description: 'Icon displayed next to the title of the panel.'

        field :tooltip,
          type: Types::Analytics::Dashboards::PanelTooltipType,
          null: true,
          description: 'Tooltip for the panel containing descriptive text and an optional link.'

        field :grid_attributes,
          type: GraphQL::Types::JSON,
          null: true,
          description: 'Description of the position and size of the panel.'

        field :query_overrides,
          type: GraphQL::Types::JSON,
          null: true,
          description: 'Overrides for the visualization query object.'

        field :visualization,
          type: Types::Analytics::Dashboards::VisualizationType,
          null: true,
          description: 'Visualization of the panel.',
          resolver: Resolvers::Analytics::Dashboards::VisualizationResolver

        field :views,
          type: [Types::Analytics::Dashboards::ViewType],
          null: false,
          description: 'Visualizations the user can switch between within the panel.',
          resolver: Resolvers::Analytics::Dashboards::ViewsResolver
      end
    end
  end
end
