# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module GroupSecrets
      class Update < BaseMutation
        graphql_name 'GroupSecretUpdate'

        include ResolvesGroup
        include Gitlab::InternalEventsTracking
        include Helpers::ErrorMessagesHelpers
        include ::SecretsManagement::MutationErrorHandling
        include ::SecretsManagement::RequiresActiveNamespace
        include ::SecretsManagement::EnforcesWriteEntitlement

        enforces_write_entitlement_for :group_secret, find_by: :group_path

        authorize :update_secret
        authorize_granular_token permissions: :update_secret,
          boundary_argument: :group_path, boundary_type: :group

        argument :group_path, GraphQL::Types::ID,
          required: true,
          description: 'Group of the secret.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the group secret to update.'

        argument :description, GraphQL::Types::String,
          required: false,
          description: 'New description of the group secret.'

        argument :secret, GraphQL::Types::String,
          required: false,
          description: 'New value of the group secret.'

        argument :environment, GraphQL::Types::String,
          required: false,
          description: 'New environment that can access the secret.'

        argument :protected, GraphQL::Types::Boolean,
          required: false,
          description: 'Whether the secret is only accessible from protected branches.'

        argument :rotation_interval_days, GraphQL::Types::Int,
          required: false,
          description: 'Number of days between rotation reminders for the secret.'

        argument :metadata_cas, GraphQL::Types::Int,
          required: true,
          description: 'This should match the current metadata version of the group secret being updated.'

        field :group_secret,
          Types::SecretsManagement::GroupSecretType,
          null: true,
          description: "Updated group secret."

        def resolve(group_path:, name:, metadata_cas:, **args)
          group = authorized_find!(group_path: group_path)
          raise_if_namespace_inactive!(group)

          result = ::SecretsManagement::GroupSecrets::UpdateService
            .new(group, current_user)
            .execute(
              name: name,
              description: args[:description],
              value: args[:secret],
              environment: args[:environment],
              protected: args[:protected],
              metadata_cas: metadata_cas,
              rotation_interval_days: args[:rotation_interval_days]
            )

          if result.success?
            track_secret_update_event(group)
            {
              group_secret: result.payload[:secret],
              errors: []
            }
          elsif result.reason == :not_found
            raise_resource_not_available_error!("Group secret does not exist.")
          else
            {
              group_secret: nil,
              errors: error_messages(result, [:secret])
            }
          end
        end

        private

        def find_object(group_path:)
          resolve_group(full_path: group_path)
        end

        def track_secret_update_event(group)
          track_internal_event(
            'update_group_ci_secret',
            user: current_user,
            namespace: group
          )
        end
      end
    end
  end
end
