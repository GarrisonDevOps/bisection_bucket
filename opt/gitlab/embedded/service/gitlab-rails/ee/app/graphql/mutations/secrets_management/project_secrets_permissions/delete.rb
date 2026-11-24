# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module ProjectSecretsPermissions
      class Delete < BaseMutation
        graphql_name 'ProjectSecretsPermissionDelete'

        include ResolvesProject
        include Gitlab::InternalEventsTracking
        include ::SecretsManagement::MutationErrorHandling
        include ::SecretsManagement::RequiresActiveNamespace
        include ::SecretsManagement::EnforcesWriteEntitlement

        enforces_write_entitlement_for :secrets_permission, find_by: :project_path

        authorize :admin_project_secrets_manager
        authorize_granular_token permissions: :delete_secrets_permission,
          boundary_argument: :project_path, boundary_type: :project

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Project from which the permissions are removed.'

        argument :principal, Types::SecretsManagement::Permissions::PrincipalInputType,
          required: true,
          description: 'User/MemberRole/Role whose access is being removed.'

        field :secrets_permission, Types::SecretsManagement::ProjectSecretsPermissionType,
          null: true,
          description: 'Secrets Permission that was deleted.'

        def resolve(project_path:, principal:)
          project = authorized_find!(project_path: project_path)
          raise_if_namespace_inactive!(project)

          result = ::SecretsManagement::ProjectSecretsPermissions::DeleteService
            .new(project, current_user)
            .execute(
              principal_id: principal.id,
              principal_type: principal.type
            )

          if result.success?
            track_permission_deletion_event(project)
            {
              secrets_permission: result.payload[:secrets_permission],
              errors: []
            }
          else
            {
              secrets_permission: nil,
              errors: [result.message]
            }
          end
        end

        private

        def find_object(project_path:)
          resolve_project(full_path: project_path)
        end

        def track_permission_deletion_event(project)
          track_internal_event(
            'delete_project_secrets_permission',
            user: current_user,
            namespace: project.namespace,
            project: project
          )
        end
      end
    end
  end
end
