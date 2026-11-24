# frozen_string_literal: true

module Types
  # rubocop: disable Graphql/AuthorizeTypes
  class EpicDescendantWeightSumType < BaseObject
    graphql_name 'EpicDescendantWeights'
    description 'Total weight of open and closed descendant issues'

    field :closed_issues,
      GraphQL::Types::Int,
      null: true,
      description: 'Total weight of completed (closed) issues in the epic, including epic descendants.',
      deprecated: { reason: 'Use `closedIssuesTotal`', milestone: '16.6' }
    field :closed_issues_total,
      GraphQL::Types::BigInt,
      null: true,
      description: 'Total weight of completed (closed) issues in this epic, including epic descendants,
    encoded as a string.'
    field :opened_issues,
      GraphQL::Types::Int,
      null: true,
      description: 'Total weight of opened issues in the epic, including epic descendants.',
      deprecated: { reason: 'Use `OpenedIssuesTotal`', milestone: '16.6' }
    field :opened_issues_total,
      GraphQL::Types::BigInt,
      null: true,
      description: 'Total weight of opened issues in the epic, including epic descendants, encoded as a string.'
  end
  # rubocop: enable Graphql/AuthorizeTypes
end
