# frozen_string_literal: true

module Types
  module WorkItems
    class AvailabilityScopeEnum < BaseEnum
      graphql_name 'WorkItemAvailabilityScope'
      description 'Scope to which a work item type availability change applies'

      value 'THIS', 'Apply only to the namespace.', value: :this
      value 'ALL_CHILDREN',
        'Apply to the namespace and propagate to all existing child namespaces.',
        value: :all_children
    end
  end
end
