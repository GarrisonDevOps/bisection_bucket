# frozen_string_literal: true

module Types
  module WorkItems
    class RelativeDateInputType < BaseInputObject
      graphql_name 'WorkItemRelativeDateInput'
      description 'Date relative to today, in the instance time zone.'

      argument :amount, GraphQL::Types::Int,
        required: true,
        description: 'Number of units, from -9999 to 9999. Negative values are in the past, ' \
          'positive values are in the future, and 0 is today.',
        validates: { numericality: { within: -::Gitlab::RelativeDate::MAX_AMOUNT..::Gitlab::RelativeDate::MAX_AMOUNT } }

      argument :unit, ::Types::WorkItems::RelativeDateUnitEnum,
        required: true,
        description: 'Unit of `amount`.'
    end
  end
end
