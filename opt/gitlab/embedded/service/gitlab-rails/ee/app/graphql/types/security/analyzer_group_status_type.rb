# frozen_string_literal: true

module Types
  module Security
    class AnalyzerGroupStatusType < BaseObject
      graphql_name 'AnalyzerGroupStatusType'
      description 'Counts for each analyzer status in the group and subgroups.'
      authorize :read_security_inventory

      field :namespace_id,
        type: GraphQL::Types::Int,
        null: false,
        description: 'Namespace ID.'

      field :analyzer_type,
        type: AnalyzerTypeForStatusEnum,
        null: false,
        description: 'Analyzer type.'

      field :success,
        type: GraphQL::Types::Int,
        null: false,
        description: 'Number of projects where `analyzer_type` completed successfully.'

      field :failure,
        type: GraphQL::Types::Int,
        null: false,
        description: 'Number of projects where `analyzer_type` failed to execute.'

      field :stale,
        type: GraphQL::Types::Int,
        null: false,
        description:
          'Number of projects where `analyzer_type` has not run in three consecutive pipelines in the default branch.'

      field :not_configured,
        type: GraphQL::Types::Int,
        null: false,
        description: 'Number of projects where `analyzer_type` is not configured.'

      field :total_projects_count,
        type: GraphQL::Types::Int,
        null: false,
        description: 'Total number of projects descending from the group.'

      field :updated_at,
        type: GraphQL::Types::ISO8601DateTime,
        null: false,
        description: 'Timestamp of when the status was last updated.'
    end
  end
end
