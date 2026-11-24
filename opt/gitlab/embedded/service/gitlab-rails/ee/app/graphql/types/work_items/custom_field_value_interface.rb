# frozen_string_literal: true

module Types
  module WorkItems
    module CustomFieldValueInterface
      include ::Types::BaseInterface

      graphql_name 'WorkItemCustomFieldValue'

      field :custom_field, ::Types::Issuables::CustomFieldType,
        null: false,
        description: 'Custom field associated with the custom field value.',
        scopes: [:api, :read_api, :ai_workflows]

      def self.resolve_type(object, *)
        if object[:custom_field].field_type_text?
          Types::WorkItems::TextFieldValueType
        elsif object[:custom_field].field_type_number?
          Types::WorkItems::NumberFieldValueType
        elsif object[:custom_field].field_type_date?
          Types::WorkItems::DateFieldValueType
        elsif object[:custom_field].field_type_select?
          Types::WorkItems::SelectFieldValueType
        end
      end

      orphan_types(
        Types::WorkItems::TextFieldValueType,
        Types::WorkItems::NumberFieldValueType,
        Types::WorkItems::SelectFieldValueType,
        Types::WorkItems::DateFieldValueType
      )
    end
  end
end
