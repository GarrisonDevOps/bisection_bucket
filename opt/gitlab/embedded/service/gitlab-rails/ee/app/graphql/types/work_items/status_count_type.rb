# frozen_string_literal: true

module Types
  module WorkItems
    # rubocop:disable Graphql/AuthorizeTypes -- Authorized at the resolver level
    class StatusCountType < BaseObject
      graphql_name 'WorkItemStatusCount'
      description 'Represents a status with its work item count'

      field :status, Types::WorkItems::StatusType,
        null: false,
        experiment: { milestone: '18.4' },
        description: 'Status of the work items.'

      field :count, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '18.4' },
        description: 'Work item count for the status. Shows "999+" when count exceeds 999.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
