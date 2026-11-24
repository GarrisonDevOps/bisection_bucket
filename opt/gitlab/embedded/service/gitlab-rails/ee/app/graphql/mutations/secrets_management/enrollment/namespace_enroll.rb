# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module Enrollment
      class NamespaceEnroll < BaseMutation
        graphql_name 'NamespaceSecretsManagerEnroll'

        include Mutations::ResolvesGroup
        include Gitlab::InternalEventsTracking
        include ::SecretsManagement::MutationErrorHandling
        include ::SecretsManagement::RequiresActiveNamespace

        authorize :create_secrets_manager_enrollment
        authorize_granular_token permissions: :create_secrets_manager_enrollment,
          boundary_argument: :namespace_path, boundary_type: :group

        argument :namespace_path,
          GraphQL::Types::ID,
          required: true,
          description: 'Full path of the namespace to enroll.'

        field :enrollment,
          Types::SecretsManagement::EnrollmentType,
          null: true,
          description: 'Enrollment record.'

        def resolve(namespace_path:)
          raise_resource_not_available_error! unless ::Gitlab.com? # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- namespace enrollment is SaaS only

          group = authorized_find!(group_path: namespace_path)
          raise_if_namespace_inactive!(group)

          result = ::SecretsManagement::NamespaceEnrollmentService
            .new(group, current_user: current_user)
            .enroll

          if result.success?
            track_internal_event('enroll_secrets_manager_for_namespace', namespace: group, user: current_user)
          end

          {
            enrollment: result.success? ? result.payload[:enrollment] : nil,
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
