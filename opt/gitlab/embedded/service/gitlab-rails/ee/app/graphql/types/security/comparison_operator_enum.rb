# frozen_string_literal: true

module Types
  module Security
    class ComparisonOperatorEnum < Types::BaseEnum
      graphql_name 'ComparisonOperator'
      description 'Comparison operators for filtering'

      value 'LESS_THAN_OR_EQUAL_TO',
        value: 'less_than_or_equal_to',
        description: 'Less than or equal to (<=).'

      value 'EQUAL_TO',
        value: 'equal_to',
        description: 'Equal to (=).'

      value 'GREATER_THAN_OR_EQUAL_TO',
        value: 'greater_than_or_equal_to',
        description: 'Greater than or equal to (>=).'
    end
  end
end
