# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module Enrollment
      class NamespaceUnenroll < BaseMutation
        graphql_name 'NamespaceSecretsManagerUnenroll'

        include Mutations::ResolvesGroup
        include Gitlab::InternalEventsTracking
        include ::SecretsManagement::MutationErrorHandling

        authorize :delete_secrets_manager_enrollment
        authorize_granular_token permissions: :delete_secrets_manager_enrollment,
          boundary_argument: :namespace_path, boundary_type: :group

        argument :namespace_path,
          GraphQL::Types::ID,
          required: true,
          description: 'Full path of the namespace to unenroll.'

        field :enrollment,
          Types::SecretsManagement::EnrollmentType,
          null: true,
          description: 'Enrollment record.'

        def resolve(namespace_path:)
          raise_resource_not_available_error! unless ::Gitlab.com? # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- namespace enrollment is SaaS only

          group = authorized_find!(group_path: namespace_path)

          result = ::SecretsManagement::NamespaceEnrollmentService
            .new(group, current_user: current_user)
            .unenroll

          if result.success?
            track_internal_event('unenroll_secrets_manager_for_namespace', namespace: group, user: current_user)
          end

          {
            enrollment: nil,
            errors: result.success? ? [] : [result.message]
          }
        end

        private

        def find_object(group_path:)
          resolve_group(full_path: group_path)
        end
      end
    end
  end
end
