# frozen_string_literal: true

module Types
  module SecretsManagement
    # rubocop: disable Graphql/AuthorizeTypes -- `object` is a hash, authorization is handled in the resolver
    class InstanceEnrollmentType < BaseObject
      graphql_name 'SecretsManagerInstanceEnrollment'
      description 'Representation of a Secrets Manager instance enrollment.'

      authorize_granular_token permissions: :read_secrets_manager_enrollment,
        boundary: :instance,
        boundary_type: :instance,
        assignable_when: [:admin, :self_managed]

      field :enrolled,
        GraphQL::Types::Boolean,
        null: false,
        experiment: { milestone: '19.3' },
        description: 'Indicates Secrets Manager is enrolled at the instance level.'

      field :beta,
        GraphQL::Types::Boolean,
        null: false,
        experiment: { milestone: '19.3' },
        description: 'Indicates the instance enrollment is part of the free beta cohort.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
