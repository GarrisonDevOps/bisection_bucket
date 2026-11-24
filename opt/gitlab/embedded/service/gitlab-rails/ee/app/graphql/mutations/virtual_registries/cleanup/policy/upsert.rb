# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Cleanup
      module Policy
        class Upsert < ::Mutations::BaseMutation
          graphql_name 'VirtualRegistriesCleanupPolicyUpsert'
          description 'Create or update virtual registries cleanup policy for a root group.'

          include Mutations::ResolvesGroup

          authorize :update_virtual_registry_cleanup_policy
          authorize_granular_token permissions: :update_virtual_registry_cleanup_policy,
            boundary_argument: :full_path, boundary_type: :group

          argument :full_path,
            GraphQL::Types::ID,
            required: true,
            description: 'Group path for the group virtual registries.'

          argument :enabled,
            GraphQL::Types::Boolean,
            required: false,
            validates: { allow_null: false },
            description: 'Enable or disable the virtual registries cleanup policy. Default is `false`.'

          argument :keep_n_days_after_download, GraphQL::Types::Int,
            validates: { allow_null: false },
            required: false,
            description: 'Keep packages for the period after download. Range is 1-365. Default is 30.'

          argument :cadence, GraphQL::Types::Int,
            required: false,
            validates: { allow_null: false },
            description: 'Job cadence for the cleanup process. Allowed values are 1, 7, 14, 30, 90. Default is 7.'

          argument :notify_on_success, GraphQL::Types::Boolean,
            required: false,
            validates: { allow_null: false },
            description: 'Whether to notify group owners when cleanup runs succeed. Default is `false`.'

          argument :notify_on_failure, GraphQL::Types::Boolean,
            required: false,
            validates: { allow_null: false },
            description: 'Whether to notify group owners when cleanup runs fail. Default is `false`.'

          field :virtual_registries_cleanup_policy,
            ::Types::VirtualRegistries::Cleanup::PolicyType,
            null: true,
            description: 'Virtual registries cleanup policy after mutation.'

          def resolve(full_path:, **args)
            group = authorized_find!(full_path:)

            raise_resource_not_available_error! unless virtual_registries_enabled?(group)

            result = ::VirtualRegistries::Cleanup::Policies::CreateOrUpdateService
              .new(group: group, current_user: current_user, params: args)
              .execute

            {
              virtual_registries_cleanup_policy: result.payload[:virtual_registries_cleanup_policy],
              errors: result.errors
            }
          end

          private

          def find_object(full_path:)
            resolve_group(full_path:)
          end

          def authorized_resource?(group)
            super(group&.virtual_registry_policy_subject)
          end

          def virtual_registries_enabled?(group)
            ::VirtualRegistries::Packages::Maven.feature_enabled?(group)
          end
        end
      end
    end
  end
end
