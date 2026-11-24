# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module GroupSecretsPermissions
      class Delete < BaseMutation
        graphql_name 'GroupSecretsPermissionDelete'

        include ResolvesGroup
        include Gitlab::InternalEventsTracking
        include ::SecretsManagement::MutationErrorHandling
        include ::SecretsManagement::RequiresActiveNamespace
        include ::SecretsManagement::EnforcesWriteEntitlement

        enforces_write_entitlement_for :secrets_permission, find_by: :group_path

        authorize :delete_secrets_permission
        authorize_granular_token permissions: :delete_secrets_permission,
          boundary_argument: :group_path, boundary_type: :group

        argument :group_path, GraphQL::Types::ID,
          required: true,
          description: 'Group permissions for the secret.'

        argument :principal, Types::SecretsManagement::Permissions::PrincipalInputType,
          required: true,
          description: 'Whose permission to be deleted.'

        field :secrets_permission, Types::SecretsManagement::GroupSecretsPermissionType,
          null: true,
          description: 'Deleted Secrets Permission.'

        def resolve(group_path:, principal:)
          group = authorized_find!(group_path: group_path)
          raise_if_namespace_inactive!(group)

          result = ::SecretsManagement::GroupSecretsPermissions::DeleteService
            .new(group, current_user)
            .execute(
              principal_id: principal.id,
              principal_type: principal.type
            )

          if result.success?
            track_permission_deletion_event(group)
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

        def find_object(group_path:)
          resolve_group(full_path: group_path)
        end

        def track_permission_deletion_event(group)
          track_internal_event(
            'delete_group_secrets_permission',
            user: current_user,
            namespace: group
          )
        end
      end
    end
  end
end
