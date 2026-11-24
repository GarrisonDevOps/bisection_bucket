# frozen_string_literal: true

module Types
  module WorkItems
    module WidgetDefinitions
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization too granular, parent type is authorized
      class ProgressType < BaseObject
        graphql_name 'WorkItemWidgetDefinitionProgress'
        description 'Represents a progress widget definition'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetDefinitionInterface

        field :show_popover, GraphQL::Types::Boolean,
          null: true,
          description: 'Indicates whether to show the progress popover.',
          experiment: { milestone: '18.8' }

        def show_popover
          object.widget_options&.dig(:show_popover)
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
