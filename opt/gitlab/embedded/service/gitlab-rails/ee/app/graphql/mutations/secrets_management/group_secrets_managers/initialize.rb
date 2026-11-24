# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module GroupSecretsManagers
      class Initialize < BaseMutation
        graphql_name 'GroupSecretsManagerInitialize'

        include Mutations::ResolvesGroup
        include ::SecretsManagement::MutationErrorHandling
        include ::SecretsManagement::RequiresActiveNamespace
        include ::SecretsManagement::EnforcesWriteEntitlement
        include ::SecretsManagement::EnforcesInitializeRateLimit

        enforces_write_entitlement_for :group_secrets_manager, find_by: :group_path

        authorize :provision_secrets_manager
        authorize_granular_token permissions: :provision_secrets_manager,
          boundary_argument: :group_path, boundary_type: :group

        argument :group_path,
          GraphQL::Types::ID,
          required: true,
          description: 'Group of the secrets manager.'

        field :group_secrets_manager,
          Types::SecretsManagement::GroupSecretsManagerType,
          null: true,
          description: "Group secrets manager."

        def resolve(group_path:)
          group = authorized_find!(group_path: group_path)
          raise_if_namespace_inactive!(group)
          return initialize_rate_limited_response(:group_secrets_manager) if initialize_rate_limited?(group)

          result = ::SecretsManagement::GroupSecretsManagers::InitializeService
            .new(group, current_user)
            .execute

          if result.success?
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

        def find_object(group_path:)
          resolve_group(full_path: group_path)
        end
      end
    end
  end
end
