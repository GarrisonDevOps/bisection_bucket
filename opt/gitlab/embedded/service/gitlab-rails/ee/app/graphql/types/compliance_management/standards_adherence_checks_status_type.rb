# frozen_string_literal: true

module Types
  module ComplianceManagement
    # rubocop: disable Graphql/AuthorizeTypes -- authorization in RefreshAdherenceChecks Mutation
    class StandardsAdherenceChecksStatusType < ::Types::BaseObject
      graphql_name 'StandardsAdherenceChecksStatus'
      description 'Progress of standards adherence checks'

      field :started_at, Types::TimeType,
        null: false,
        description: 'UTC timestamp when the adherence checks scan was started.'

      field :checks_completed, GraphQL::Types::Int,
        null: false,
        description: 'Number of adherence checks successfully completed.'

      field :total_checks, GraphQL::Types::Int,
        null: false,
        description: 'Number of adherence checks multiplied by the number of projects in the group.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
