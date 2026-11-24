# frozen_string_literal: true

module Types
  module WorkItems
    module WidgetDefinitions
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization too granular, parent type is authorized
      class WeightType < BaseObject
        graphql_name 'WorkItemWidgetDefinitionWeight'
        description 'Represents a weight widget definition'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetDefinitionInterface

        field :editable, GraphQL::Types::Boolean,
          null: false,
          description: 'Indicates whether editable weight is available.',
          deprecated: {
            reason: 'All work item types with weight widget now support editing',
            milestone: '18.11'
          }

        field :roll_up, GraphQL::Types::Boolean,
          null: false,
          description: 'Indicates whether rolled up weight is available.',
          deprecated: {
            reason: 'All work item types with weight widget now support rolled up weight',
            milestone: '18.11'
          }

        def editable
          true
        end

        def roll_up
          true
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
