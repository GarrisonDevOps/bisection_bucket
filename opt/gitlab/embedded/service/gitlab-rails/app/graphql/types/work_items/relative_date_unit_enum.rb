# frozen_string_literal: true

module Types
  module WorkItems
    class RelativeDateUnitEnum < BaseEnum
      graphql_name 'WorkItemRelativeDateUnit'
      description 'Unit of a relative date.'

      # No `value:` mapping, so saved views store the GraphQL value and can send it back unchanged.
      value 'DAY', 'Days.'
      value 'WEEK', 'Weeks.'
      value 'MONTH', 'Months.'
      value 'YEAR', 'Years.'
    end
  end
end
