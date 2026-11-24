# frozen_string_literal: true

module Types
  module WorkItems
    class AvailabilityActionEnum < BaseEnum
      graphql_name 'WorkItemAvailabilityAction'
      description 'Action to apply to work item type availability'

      value 'ENABLE', 'Enable the work item type in the namespace.', value: :enable
      value 'DISABLE', 'Disable the work item type in the namespace.', value: :disable
    end
  end
end
