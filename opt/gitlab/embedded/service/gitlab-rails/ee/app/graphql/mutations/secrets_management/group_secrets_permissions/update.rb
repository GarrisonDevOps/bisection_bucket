# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module GroupSecretsPermissions
      class Update < BaseMutation
        graphql_name 'GroupSecretsPermissionUpdate'

        include ResolvesGroup
        include Gitlab::InternalEventsTracking
        include Helpers::ErrorMessagesHelpers
        include ::SecretsManagement::MutationErrorHandling
        include ::SecretsManagement::RequiresActiveNamespace
        include ::SecretsManagement::EnforcesWriteEntitlement

        enforces_write_entitlement_for :secrets_permission, find_by: :group_path

        authorize :update_secrets_permission
        authorize_granular_token permissions: :update_secrets_permission,
          boundary_argument: :group_path, boundary_type: :group

        argument :group_path, GraphQL::Types::ID,
          required: true,
          description: 'Group to which the permissions are added.'

        argument :principal, Types::SecretsManagement::Permissions::PrincipalInputType,
          required: true,
          description: 'User/MemberRole/Role that is provided access.'

        argument :actions, [Types::SecretsManagement::Permissions::ActionEnum],
          required: true,
          description: 'Actions that can be performed on secrets.'

        argument :expired_at, GraphQL::Types::ISO8601Date, required: false,
          description: "Expiration date for Secret Permission (optional)."

        field :secrets_permission, Types::SecretsManagement::GroupSecretsPermissionType,
          null: true,
          description: 'Secrets Permission that was created.'

        def resolve(group_path:, principal:, actions:, expired_at: nil)
          group = authorized_find!(group_path: group_path)
          raise_if_namespace_inactive!(group)

          result = ::SecretsManagement::GroupSecretsPermissions::UpdateService
            .new(group, current_user)
            .execute(
              principal_id: principal.id,
              principal_type: principal.type,
              actions: actions,
              expired_at: expired_at
            )

          if result.success?
            track_permission_update_event(group)
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

        def find_object(group_path:)
          resolve_group(full_path: group_path)
        end

        def track_permission_update_event(group)
          track_internal_event(
            'update_group_secrets_permission',
            user: current_user,
            namespace: group
          )
        end
      end
    end
  end
end
