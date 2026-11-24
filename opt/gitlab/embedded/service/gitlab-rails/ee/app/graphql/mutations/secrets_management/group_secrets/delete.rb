# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module GroupSecrets
      class Delete < BaseMutation
        graphql_name 'GroupSecretDelete'

        include ResolvesGroup
        include Gitlab::InternalEventsTracking
        include ::SecretsManagement::MutationErrorHandling
        include ::SecretsManagement::RequiresActiveNamespace

        authorize :delete_secret
        authorize_granular_token permissions: :delete_secret,
          boundary_argument: :group_path, boundary_type: :group

        argument :group_path, GraphQL::Types::ID,
          required: true,
          description: 'Group of the secret.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the group secret to delete.'

        field :group_secret,
          Types::SecretsManagement::GroupSecretType,
          null: true,
          description: "Deleted group secret."

        def resolve(group_path:, name:)
          group = authorized_find!(group_path: group_path)
          raise_if_namespace_inactive!(group)

          result = ::SecretsManagement::GroupSecrets::DeleteService
            .new(group, current_user)
            .execute(name)

          if result.success?
            track_secret_deletion_event(group)
            {
              group_secret: result.payload[:secret],
              errors: []
            }
          elsif result.reason == :not_found
            raise_resource_not_available_error!("Group secret does not exist.")
          else
            {
              group_secret: nil,
              errors: [result.message]
            }
          end
        end

        private

        def find_object(group_path:)
          resolve_group(full_path: group_path)
        end

        def track_secret_deletion_event(group)
          track_internal_event(
            'delete_group_ci_secret',
            user: current_user,
            namespace: group
          )
        end
      end
    end
  end
end
