# frozen_string_literal: true

module Types
  module WorkItems
    module WidgetDefinitions
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization too granular, parent type is authorized
      class CustomFieldsType < BaseObject
        graphql_name 'WorkItemWidgetDefinitionCustomFields'
        description 'Represents a custom fields widget definition'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetDefinitionInterface

        field :custom_field_values,
          null: true,
          description: 'Custom field values associated to the work item.',
          resolver: ::Resolvers::WorkItems::TypeCustomFieldValuesResolver,
          experiment: { milestone: '17.10' }
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
