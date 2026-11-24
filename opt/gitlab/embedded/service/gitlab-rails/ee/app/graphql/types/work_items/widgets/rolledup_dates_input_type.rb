# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      class RolledupDatesInputType < BaseInputObject
        graphql_name 'WorkItemWidgetRolledupDatesInput'

        argument :start_date_fixed,
          ::Types::DateType,
          required: false,
          description: 'Fixed start date for the work item.'

        argument :start_date_is_fixed,
          ::GraphQL::Types::Boolean,
          required: false,
          default_value: false,
          description: 'When start_date_fixed is not provided it defaults to `false`.'

        argument :due_date_fixed,
          ::Types::DateType,
          required: false,
          description: 'Fixed due date for the work item.'

        argument :due_date_is_fixed,
          ::GraphQL::Types::Boolean,
          required: false,
          default_value: false,
          description: 'When due_date_fixed is not provided it defaults to `false`.'
      end
    end
  end
end
