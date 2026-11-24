# frozen_string_literal: true

module Types
  module WorkItems
    class DecisionResolutionInputType < BaseInputObject
      graphql_name 'WorkItemDecisionResolutionInput'
      description 'Attributes for recording a work item decision as resolved at creation.'

      argument :decision, GraphQL::Types::String,
        required: true,
        description: 'Decision that was made, recorded as the selected option of the work item decision.'

      argument :rationale, GraphQL::Types::String,
        required: false,
        description: 'Reasoning behind the decision.'

      argument :resolved_by_id, ::Types::GlobalIDType[::User],
        required: false,
        prepare: ->(global_id, _ctx) { global_id&.model_id },
        description: 'Global ID of the user who resolved the decision. Defaults to the current user.'
    end
  end
end
