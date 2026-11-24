# frozen_string_literal: true

module Types
  module Issuables
    class CustomFieldTypeEnum < BaseEnum
      graphql_name 'CustomFieldType'
      description 'Type of custom field'

      ::Issuables::CustomField.field_types.each_key do |type|
        value type.upcase, value: type, description: "#{type.humanize} field type."
      end
    end
  end
end
