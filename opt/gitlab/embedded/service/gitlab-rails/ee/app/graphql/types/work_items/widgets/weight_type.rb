# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      # Disabling widget level authorization as it might be too granular
      # and we already authorize the parent work item
      # rubocop:disable Graphql/AuthorizeTypes
      class WeightType < BaseObject
        graphql_name 'WorkItemWidgetWeight'
        description 'Represents a weight widget'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetInterface

        field :widget_definition, ::Types::WorkItems::WidgetDefinitions::WeightType,
          null: true,
          description: 'Weight widget definition.',
          deprecated: {
            reason: 'All work item types with weight widget now support editing and rolled up weight',
            milestone: '18.11'
          }

        field :weight, GraphQL::Types::Int,
          null: true, description: 'Weight of the work item.'

        field :rolled_up_weight, GraphQL::Types::Int,
          null: true, description: 'Rolled up weight from descendant work items.',
          experiment: { milestone: '17.2' }

        field :rolled_up_completed_weight, GraphQL::Types::Int, # rubocop:disable GraphQL/ExtractType -- No need to extract 2 integers into an extra type
          null: true, description: 'Rolled up weight from closed descendant work items.',
          experiment: { milestone: '17.3' }
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
