# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module Enrollment
      class InstanceUnenroll < BaseMutation
        graphql_name 'InstanceSecretsManagerUnenroll'

        include Gitlab::InternalEventsTracking
        include ::SecretsManagement::MutationErrorHandling

        authorize :delete_secrets_manager_enrollment
        authorize_granular_token permissions: :delete_secrets_manager_enrollment,
          boundary: :instance, boundary_type: :instance

        def resolve
          authorize!(:global)

          result = ::SecretsManagement::InstanceEnrollmentService
            .new(current_user: current_user)
            .unenroll

          track_internal_event('unenroll_secrets_manager_for_instance', user: current_user) if result.success?

          {
            errors: result.success? ? [] : [result.message]
          }
        end
      end
    end
  end
end
