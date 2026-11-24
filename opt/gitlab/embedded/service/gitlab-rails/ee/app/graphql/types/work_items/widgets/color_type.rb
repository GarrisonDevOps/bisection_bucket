# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      # rubocop:disable Graphql/AuthorizeTypes -- Disabling widget level authorization as it might be too granular
      class ColorType < BaseObject
        graphql_name 'WorkItemWidgetColor'
        description 'Represents a color widget'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetInterface

        field :color, GraphQL::Types::String, null: true, description: 'Color of the Work Item.'

        field :text_color, GraphQL::Types::String, null: true, description: 'Text color generated for the Work Item.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
