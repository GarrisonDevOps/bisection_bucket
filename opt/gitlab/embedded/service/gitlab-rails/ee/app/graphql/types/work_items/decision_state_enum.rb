# frozen_string_literal: true

module Types
  module WorkItems
    class DecisionStateEnum < BaseEnum
      graphql_name 'WorkItemDecisionState'
      description 'State of a decision in the decision log of a work item'

      value 'ACTIVE', 'Decision is open and awaiting resolution.', value: :active
      value 'RESOLVED', 'Decision has been resolved.', value: :resolved
      value 'ARCHIVED', 'Decision was resolved and later archived.', value: :archived
    end
  end
end
