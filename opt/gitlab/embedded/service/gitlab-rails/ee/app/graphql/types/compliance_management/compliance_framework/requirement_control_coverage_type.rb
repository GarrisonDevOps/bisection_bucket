# frozen_string_literal: true

module Types
  module ComplianceManagement
    module ComplianceFramework
      # rubocop: disable Graphql/AuthorizeTypes -- Authorized in resolver.
      class RequirementControlCoverageType < ::Types::BaseObject
        graphql_name 'RequirementControlCoverage'
        description 'Compliance control coverage statistics across all requirements.'

        field :passed, GraphQL::Types::Int,
          null: false, description: 'Number of controls that passed compliance checks.'

        field :failed, GraphQL::Types::Int,
          null: false, description: 'Number of controls that failed compliance checks.'

        field :pending, GraphQL::Types::Int,
          null: false, description: 'Number of controls pending evaluation.'

        field :not_applicable, GraphQL::Types::Int,
          null: false, description: 'Number of controls not applicable to the project.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
