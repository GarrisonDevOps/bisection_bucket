# frozen_string_literal: true

module Types
  module Analytics
    module Dashboards
      # rubocop:disable Graphql/AuthorizeTypes -- authorized by parent type
      class ViewType < BaseObject
        graphql_name 'CustomizableDashboardPanelView'
        description 'Represents a view that can be selected within a customizable dashboard panel.'

        field :text,
          type: GraphQL::Types::String,
          null: true,
          description: 'Label shown in the segmented control for the view.'

        field :visualization,
          type: Types::Analytics::Dashboards::VisualizationType,
          null: true,
          description: 'Visualization rendered when the view is selected.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
