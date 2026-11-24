# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module Enrollment
      class InstanceEnroll < BaseMutation
        graphql_name 'InstanceSecretsManagerEnroll'

        include Gitlab::InternalEventsTracking
        include ::SecretsManagement::MutationErrorHandling

        authorize :create_secrets_manager_enrollment
        authorize_granular_token permissions: :create_secrets_manager_enrollment,
          boundary: :instance, boundary_type: :instance

        def resolve
          authorize!(:global)

          result = ::SecretsManagement::InstanceEnrollmentService
            .new(current_user: current_user)
            .enroll

          track_internal_event('enroll_secrets_manager_for_instance', user: current_user) if result.success?

          {
            errors: result.success? ? [] : [result.message]
          }
        end
      end
    end
  end
end
