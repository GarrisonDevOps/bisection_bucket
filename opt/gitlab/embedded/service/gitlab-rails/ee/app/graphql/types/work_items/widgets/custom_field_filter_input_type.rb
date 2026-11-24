# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      class CustomFieldFilterInputType < BaseInputObject
        graphql_name 'WorkItemWidgetCustomFieldFilterInputType'

        argument :custom_field_id, ::Types::GlobalIDType[::Issuables::CustomField],
          required: false,
          description: copy_field_description(Types::Issuables::CustomFieldType, :id),
          prepare: ->(id, _ctx) { id&.model_id }

        argument :custom_field_name, GraphQL::Types::String,
          required: false,
          description: copy_field_description(Types::Issuables::CustomFieldType, :name)

        argument :selected_option_ids, [::Types::GlobalIDType[::Issuables::CustomFieldSelectOption]],
          required: false,
          validates: { length: { maximum: ::WorkItems::SharedFilterArguments::MAX_FIELD_LIMIT } },
          description: "Global IDs of the selected options for custom fields with select type " \
            "(maximum is #{::WorkItems::SharedFilterArguments::MAX_FIELD_LIMIT} IDs).",
          prepare: ->(ids, _ctx) { ids&.map(&:model_id) }

        argument :selected_option_values, [GraphQL::Types::String],
          required: false,
          validates: { length: { maximum: ::WorkItems::SharedFilterArguments::MAX_FIELD_LIMIT } },
          description: "Values of the selected options for custom fields with select type " \
            "(maximum is #{::WorkItems::SharedFilterArguments::MAX_FIELD_LIMIT} values)."

        validates exactly_one_of: [:custom_field_id, :custom_field_name]
        validates exactly_one_of: [:selected_option_ids, :selected_option_values]
      end
    end
  end
end
