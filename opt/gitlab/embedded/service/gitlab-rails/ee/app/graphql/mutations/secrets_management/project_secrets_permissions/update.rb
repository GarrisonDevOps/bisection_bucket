# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module ProjectSecretsPermissions
      class Update < BaseMutation
        graphql_name 'ProjectSecretsPermissionUpdate'

        include ResolvesProject
        include Gitlab::InternalEventsTracking
        include Helpers::ErrorMessagesHelpers
        include ::SecretsManagement::MutationErrorHandling
        include ::SecretsManagement::RequiresActiveNamespace
        include ::SecretsManagement::EnforcesWriteEntitlement

        enforces_write_entitlement_for :secrets_permission, find_by: :project_path

        authorize :admin_project_secrets_manager
        authorize_granular_token permissions: :update_secrets_permission,
          boundary_argument: :project_path, boundary_type: :project

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Project to which the permissions are added.'

        argument :principal, Types::SecretsManagement::Permissions::PrincipalInputType,
          required: true,
          description: 'User/MemberRole/Role that is provided access.'

        argument :actions, [Types::SecretsManagement::Permissions::ActionEnum],
          required: true,
          description: 'Actions that can be performed on secrets.'

        argument :expired_at, GraphQL::Types::ISO8601Date, required: false,
          description: "Expiration date for Secret Permission (optional)."

        field :secrets_permission, Types::SecretsManagement::ProjectSecretsPermissionType,
          null: true,
          description: 'Secrets Permission that was created.'

        def resolve(project_path:, principal:, actions:, expired_at: nil)
          project = authorized_find!(project_path: project_path)
          raise_if_namespace_inactive!(project)

          result = ::SecretsManagement::ProjectSecretsPermissions::UpdateService
            .new(project, current_user)
            .execute(
              principal_id: principal.id,
              principal_type: principal.type,
              actions: actions,
              expired_at: expired_at
            )

          if result.success?
            track_permission_update_event(project)
            {
              secrets_permission: result.payload[:secrets_permission],
              errors: []
            }
          else
            {
              secrets_permission: nil,
              errors: error_messages(result, [:secrets_permission])
            }
          end
        end

        private

        def find_object(project_path:)
          resolve_project(full_path: project_path)
        end

        def track_permission_update_event(project)
          track_internal_event(
            'update_project_secrets_permission',
            user: current_user,
            namespace: project.namespace,
            project: project
          )
        end
      end
    end
  end
end
