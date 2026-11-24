# frozen_string_literal: true

module Types
  module WorkItems
    class DecisionOptionUpdateInputType < BaseInputObject
      graphql_name 'WorkItemDecisionOptionUpdateInput'
      description 'Attributes to update on an existing option of a work item decision.'

      argument :id, ::Types::GlobalIDType[::WorkItems::DecisionOption],
        required: true,
        prepare: ->(global_id, _ctx) { global_id.model_id },
        description: 'Global ID of the decision option.'

      argument :content, GraphQL::Types::String,
        required: false,
        validates: { allow_blank: false },
        description: 'Content of the decision option.'

      argument :description, GraphQL::Types::String,
        required: false,
        validates: { allow_blank: false },
        description: 'Reasoning behind the decision option.'

      argument :selected, GraphQL::Types::Boolean,
        required: false,
        validates: { allow_null: false },
        description: 'Indicates the option is selected. Can only be updated on resolved decisions.'

      validates at_least_one_of: [:content, :description, :selected]
    end
  end
end
