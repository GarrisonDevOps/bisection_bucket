# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module GroupSecretsManagers
      class Deprovision < BaseMutation
        graphql_name 'GroupSecretsManagerDeprovision'

        include Mutations::ResolvesGroup
        include Gitlab::InternalEventsTracking
        include ::SecretsManagement::MutationErrorHandling
        include ::SecretsManagement::EnforcesWriteEntitlement

        enforces_write_entitlement_for :group_secrets_manager, find_by: :group_path

        authorize :deprovision_secrets_manager
        authorize_granular_token permissions: :deprovision_secrets_manager,
          boundary_argument: :group_path, boundary_type: :group

        argument :group_path, GraphQL::Types::ID,
          required: true,
          description: 'Group of the secrets manager.'

        field :group_secrets_manager,
          Types::SecretsManagement::GroupSecretsManagerType,
          null: true,
          description: "Group secrets manager."

        def resolve(group_path:)
          group = authorized_find!(group_path: group_path)

          result = ::SecretsManagement::GroupSecretsManagers::InitiateDeprovisionService.new(
            group.secrets_manager,
            current_user,
            group_id: group.id
          ).execute

          if result.success?
            track_event(group)
            {
              group_secrets_manager: result.payload[:group_secrets_manager],
              errors: []
            }
          else
            {
              group_secrets_manager: nil,
              errors: [result.message]
            }
          end
        end

        private

        def track_event(group)
          track_internal_event(
            'disable_ci_secrets_manager_for_group',
            namespace: group,
            user: current_user
          )
        end

        def find_object(group_path:)
          resolve_group(full_path: group_path)
        end
      end
    end
  end
end
