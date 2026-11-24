# frozen_string_literal: true

module Types
  module AlertManagement
    class PayloadAlertFieldTypeEnum < BaseEnum
      graphql_name 'AlertManagementPayloadAlertFieldType'
      description 'Values for alert field types used in the custom mapping'

      value 'ARRAY', 'Array field type.', value: 'array'
      value 'DATETIME', 'DateTime field type.', value: 'datetime'
      value 'STRING', 'String field type.', value: 'string'
      value 'NUMBER', 'Number field type.', value: 'number'
    end
  end
end
