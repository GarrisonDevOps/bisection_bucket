# frozen_string_literal: true

module Types
  module WorkItems
    module WidgetDefinitions
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization too granular, parent type is authorized
      class LabelsType < BaseObject
        graphql_name 'WorkItemWidgetDefinitionLabels'
        description 'Represents a labels widget definition'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetDefinitionInterface

        field :allows_scoped_labels, GraphQL::Types::Boolean,
          null: false,
          description: 'Indicates whether scoped labels are available.'

        def allows_scoped_labels
          resource_parent.licensed_feature_available?(:scoped_labels)
        end

        private

        def resource_parent
          context[:resource_parent]
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
