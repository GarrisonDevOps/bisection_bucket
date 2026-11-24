# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class TriggerConditionsOperatorEnum < BaseEnum
        graphql_name 'AiCatalogTriggerConditionsOperator'
        description 'Operators for a trigger condition rule.'

        value 'EQ', description: 'Equal to the value.', value: 'eq'
        value 'NE', description: 'Not equal to the value.', value: 'ne'
        value 'GT', description: 'Greater than the value.', value: 'gt'
        value 'LT', description: 'Less than the value.', value: 'lt'
        value 'CONTAINS', description: 'Contains the value.', value: 'contains'
        value 'NOT_CONTAINS', description: 'Does not contain the value.', value: 'not_contains'
        value 'IN', description: 'Included in the value.', value: 'in'
        value 'NOT_IN', description: 'Not included in the value.', value: 'not_in'
      end
    end
  end
end
