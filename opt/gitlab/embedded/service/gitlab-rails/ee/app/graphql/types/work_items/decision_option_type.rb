# frozen_string_literal: true

module Types
  module WorkItems
    # rubocop:disable Graphql/AuthorizeTypes -- authorized through the parent work item widget
    class DecisionOptionType < BaseObject
      graphql_name 'WorkItemDecisionOption'
      description 'Represents a candidate option of a work item decision.'

      authorize_granular_token skip_reason: :parent_authorizes

      field :id, ::Types::GlobalIDType[::WorkItems::DecisionOption],
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Global ID of the decision option.'

      field :content, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Content of the decision option.'

      field :description, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Reasoning behind the decision option.'

      field :recommended, GraphQL::Types::Boolean,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Indicates the option is recommended by GitLab Duo.'

      field :selected, GraphQL::Types::Boolean,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Indicates the option was selected when the decision was resolved.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
