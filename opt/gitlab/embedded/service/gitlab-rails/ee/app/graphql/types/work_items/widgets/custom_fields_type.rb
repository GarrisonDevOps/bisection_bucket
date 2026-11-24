# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      # rubocop:disable Graphql/AuthorizeTypes -- already authorized in parent type
      class CustomFieldsType < BaseObject
        graphql_name 'WorkItemWidgetCustomFields'
        description 'Represents a custom fields widget'

        authorize_granular_token skip_reason: :parent_authorizes

        implements Types::WorkItems::WidgetInterface

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :custom_field_values, [Types::WorkItems::CustomFieldValueInterface], null: true,
          description: 'Custom field values associated to the work item.',
          scopes: [:api, :read_api, :ai_workflows],
          experiment: { milestone: '17.9' } do
          argument :custom_field_ids, [::Types::GlobalIDType[::Issuables::CustomField]],
            required: false,
            description: 'Only return values for the given custom field IDs.',
            prepare: ->(global_ids, _ctx) { global_ids.map(&:model_id) }
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
