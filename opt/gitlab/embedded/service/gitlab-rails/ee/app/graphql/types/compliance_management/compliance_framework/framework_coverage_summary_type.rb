# frozen_string_literal: true

module Types
  module ComplianceManagement
    module ComplianceFramework
      # rubocop: disable Graphql/AuthorizeTypes -- Authorized in resolver.
      class FrameworkCoverageSummaryType < ::Types::BaseObject
        graphql_name 'ComplianceFrameworkCoverageSummary'
        description 'Compliance framework Coverage summary for a group.'

        field :total_projects, GraphQL::Types::Int,
          null: false, description: 'Total number of projects in the group.'

        field :covered_count, GraphQL::Types::Int,
          null: false, description: 'Number of projects covered by at least one framework.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
