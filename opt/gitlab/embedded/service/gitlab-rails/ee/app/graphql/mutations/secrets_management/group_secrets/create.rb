# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module GroupSecrets
      class Create < BaseMutation
        graphql_name 'GroupSecretCreate'

        include ResolvesGroup
        include Gitlab::InternalEventsTracking
        include Helpers::ErrorMessagesHelpers
        include ::SecretsManagement::MutationErrorHandling
        include ::SecretsManagement::RequiresActiveNamespace
        include ::SecretsManagement::EnforcesWriteEntitlement

        enforces_write_entitlement_for :group_secret, find_by: :group_path

        authorize :create_secret
        authorize_granular_token permissions: :create_secret,
          boundary_argument: :group_path, boundary_type: :group

        argument :group_path, GraphQL::Types::ID,
          required: true,
          description: 'Group of the secret.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the group secret.'

        argument :description, GraphQL::Types::String,
          required: false,
          description: 'Description of the group secret.'

        argument :secret, GraphQL::Types::String,
          required: true,
          description: 'Value of the group secret.'

        argument :environment, GraphQL::Types::String,
          required: true,
          description: 'Environment that can access the secret.'

        argument :protected, GraphQL::Types::Boolean,
          required: true,
          description: 'Whether the secret is only accessible from protected branches.'

        argument :rotation_interval_days, GraphQL::Types::Int,
          required: false,
          description: 'Number of days between rotation reminders for the secret.'

        field :group_secret,
          Types::SecretsManagement::GroupSecretType,
          null: true,
          description: "Group secret."

        def resolve(
          group_path:, name:, secret:, environment:, protected:, description: nil,
          rotation_interval_days: nil)
          group = authorized_find!(group_path: group_path)
          raise_if_namespace_inactive!(group)

          result = ::SecretsManagement::GroupSecrets::CreateService
            .new(group, current_user)
            .execute(
              name: name,
              description: description,
              value: secret,
              environment: environment,
              protected: protected,
              rotation_interval_days: rotation_interval_days
            )

          if result.success?
            track_secret_creation_event(group)
            {
              group_secret: result.payload[:secret],
              errors: []
            }
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

        def track_secret_creation_event(group)
          track_internal_event(
            'create_group_ci_secret',
            user: current_user,
            namespace: group
          )
        end
      end
    end
  end
end
