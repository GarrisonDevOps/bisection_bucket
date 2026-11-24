# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      class CustomFieldValueInputType < BaseInputObject
        graphql_name 'WorkItemWidgetCustomFieldValueInputType'

        argument :custom_field_id, ::Types::GlobalIDType[::Issuables::CustomField],
          required: true,
          description: copy_field_description(Types::Issuables::CustomFieldType, :id),
          prepare: ->(id, _ctx) { id&.model_id }

        argument :selected_option_ids, [::Types::GlobalIDType[::Issuables::CustomFieldSelectOption]],
          required: false,
          description: 'Global IDs of the selected options for custom fields with select type.',
          prepare: ->(ids, _ctx) { ids.map(&:model_id) }

        argument :number_value, GraphQL::Types::Float,
          required: false,
          description: 'Value for custom fields with number type.'

        argument :text_value, GraphQL::Types::String,
          required: false,
          description: 'Value for custom fields with text type.'

        argument :date_value, ::Types::DateType,
          required: false,
          description: 'Value for custom fields with date type.'

        validates mutually_exclusive: [:selected_option_ids, :number_value, :text_value, :date_value]
      end
    end
  end
end
