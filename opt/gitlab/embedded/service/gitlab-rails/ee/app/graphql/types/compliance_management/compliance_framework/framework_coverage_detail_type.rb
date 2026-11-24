# frozen_string_literal: true

module Types
  module ComplianceManagement
    module ComplianceFramework
      # rubocop: disable Graphql/AuthorizeTypes -- Authorized in resolver.
      class FrameworkCoverageDetailType < ::Types::BaseObject
        graphql_name 'ComplianceFrameworkCoverageDetail'
        description 'Framework coverage details for a specific compliance framework.'

        field :id, GraphQL::Types::ID,
          null: false, description: 'ID of the framework.'

        field :framework, ::Types::ComplianceManagement::ComplianceFrameworkType,
          null: false,
          description: 'Compliance framework associated with the coverage detail.'

        field :covered_count, GraphQL::Types::Int,
          null: false, description: 'Number of projects covered by the framework.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
