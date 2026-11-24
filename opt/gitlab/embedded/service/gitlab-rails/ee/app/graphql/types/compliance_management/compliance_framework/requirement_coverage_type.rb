# frozen_string_literal: true

module Types
  module ComplianceManagement
    module ComplianceFramework
      # rubocop: disable Graphql/AuthorizeTypes -- Authorized in resolver.
      class RequirementCoverageType < ::Types::BaseObject
        graphql_name 'RequirementCoverage'
        description 'Coverage statistics requirements.'

        field :passed, GraphQL::Types::Int,
          null: false, description: 'Count of passed requirements.'

        field :pending, GraphQL::Types::Int,
          null: false, description: 'Count of pending requirements.'

        field :failed, GraphQL::Types::Int,
          null: false, description: 'Count of failed requirements.'

        field :not_applicable, GraphQL::Types::Int,
          null: false, description: 'Count of requirements with only not applicable controls.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
