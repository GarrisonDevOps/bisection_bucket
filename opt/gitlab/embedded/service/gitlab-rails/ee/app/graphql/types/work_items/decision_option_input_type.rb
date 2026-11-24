# frozen_string_literal: true

module Types
  module WorkItems
    class DecisionOptionInputType < BaseInputObject
      graphql_name 'WorkItemDecisionOptionInput'
      description 'Attributes for a candidate option of a work item decision.'

      argument :content, GraphQL::Types::String,
        required: true,
        description: 'Content of the decision option.'

      argument :description, GraphQL::Types::String,
        required: false,
        description: 'Reasoning behind the decision option.'

      argument :recommended, GraphQL::Types::Boolean,
        required: false,
        description: 'Indicates the option is recommended by GitLab Duo.'
    end
  end
end
