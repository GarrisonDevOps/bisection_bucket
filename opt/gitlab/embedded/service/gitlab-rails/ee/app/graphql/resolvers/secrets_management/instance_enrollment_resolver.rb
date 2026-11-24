# frozen_string_literal: true

module Resolvers
  module SecretsManagement
    class InstanceEnrollmentResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include ::SecretsManagement::ResolverErrorHandling

      type ::Types::SecretsManagement::InstanceEnrollmentType, null: false
      description 'Check if Secrets Manager is enrolled at the instance level.'

      authorize :read_secrets_manager_enrollment

      def resolve
        authorize!(:global)

        {
          enrolled: ::SecretsManagement::InstanceEnrollment.enrolled?,
          beta: ::SecretsManagement::InstanceEnrollment.beta?
        }
      end
    end
  end
end
