# frozen_string_literal: true

module Types
  module Issuables
    class CustomFieldSelectOptionInputType < BaseInputObject
      graphql_name 'CustomFieldSelectOptionInput'
      description 'Attributes for the custom field select option'

      argument :id, ::Types::GlobalIDType[::Issuables::CustomFieldSelectOption],
        required: false,
        description: 'Global ID of the custom field select option to update. Creates a new record if not provided.',
        prepare: ->(attribute, _ctx) { attribute.model_id }

      argument :value, GraphQL::Types::String,
        required: true,
        description: copy_field_description(Types::Issuables::CustomFieldSelectOptionType, :value)
    end
  end
end
