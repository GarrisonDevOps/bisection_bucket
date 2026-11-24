# frozen_string_literal: true

module Types
  module Security
    class AttributeFilterOperatorEnum < Types::BaseEnum
      graphql_name 'AttributeFilterOperator'
      description 'Operators for filtering by security attributes'

      value 'IS_ONE_OF',
        value: 'is_one_of',
        description: 'Project has one or more of the specified attributes.'

      value 'IS_NOT_ONE_OF',
        value: 'is_not_one_of',
        description: 'Project does not have any of the specified attributes.'
    end
  end
end
