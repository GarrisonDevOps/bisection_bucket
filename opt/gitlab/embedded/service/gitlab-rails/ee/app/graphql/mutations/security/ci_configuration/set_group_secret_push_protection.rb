# frozen_string_literal: true

module Mutations
  module Security
    module CiConfiguration
      class SetGroupSecretPushProtection < BaseMutation
        graphql_name 'SetGroupSecretPushProtection'

        include Mutations::ResolvesGroup

        description 'Enable or disable secret push protection for a group.'

        argument :secret_push_protection_enabled, GraphQL::Types::Boolean, required: true,
          description: 'Whether to enable the feature.'

        argument :namespace_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the group.'

        argument :projects_to_exclude, [GraphQL::Types::Int], required: false,
          description: 'IDs of projects to exclude from the feature.'

        authorize :enable_secret_push_protection

        authorize_granular_token permissions: :update_security_setting,
          boundary_argument: :namespace_path, boundary_type: :group

        def resolve(namespace_path:, secret_push_protection_enabled:, projects_to_exclude: [])
          group = authorized_find!(group_path: namespace_path)

          raise_resource_not_available_error! 'Setting only available for group namespaces.' unless group.is_a? Group

          ::Security::Configuration::SetGroupSecretPushProtectionWorker.perform_async(group.id, secret_push_protection_enabled, current_user.id, projects_to_exclude) # rubocop:disable CodeReuse/Worker -- This is meant to be a background job

          {
            secret_push_protection_enabled: secret_push_protection_enabled,
            errors: []
          }
        end

        private

        def find_object(group_path:)
          resolve_group(full_path: group_path)
        end
      end
    end
  end
end
