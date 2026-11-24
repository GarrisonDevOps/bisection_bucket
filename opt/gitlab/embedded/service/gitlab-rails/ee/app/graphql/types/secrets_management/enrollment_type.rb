# frozen_string_literal: true

module Types
  module SecretsManagement
    class EnrollmentType < BaseObject
      graphql_name 'SecretsManagerEnrollment'
      description 'Representation of a Secrets Manager namespace enrollment.'

      authorize_granular_token permissions: :read_secrets_manager, boundary: :namespace, boundary_type: :group

      authorize :read_secrets_manager_enrollment

      field :namespace,
        Types::NamespaceType,
        null: false,
        description: 'Namespace the enrollment belongs to.'

      field :beta,
        GraphQL::Types::Boolean,
        null: false,
        experiment: { milestone: '19.3' },
        description: 'Indicates the enrollment is part of the free beta cohort.'
    end
  end
end
