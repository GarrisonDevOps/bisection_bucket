# frozen_string_literal: true

module Types
  module Analytics
    module Dashboards
      # rubocop:disable Graphql/AuthorizeTypes -- authorized by parent type
      class PanelTooltipType < BaseObject
        graphql_name 'CustomizableDashboardPanelTooltip'
        description "Tooltip for a customizable dashboard panel."

        field :description,
          type: GraphQL::Types::String,
          null: false,
          description: 'Popover text content. When `descriptionLink` is provided, ' \
            'must include %{linkStart} and %{linkEnd} placeholders around the link text.'

        field :description_link,
          type: GraphQL::Types::String,
          null: true,
          description: 'Optional URL for link insertion in the `description` ' \
            'between %{linkStart} and %{linkEnd} placeholders.',
          hash_key: :descriptionLink
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
