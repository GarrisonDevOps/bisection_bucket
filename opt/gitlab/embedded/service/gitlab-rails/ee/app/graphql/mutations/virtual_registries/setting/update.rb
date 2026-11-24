# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Setting
      class Update < ::Mutations::BaseMutation
        graphql_name 'UpdateVirtualRegistriesSetting'
        description 'Updates or creates virtual registries settings for a root group.'

        include Mutations::ResolvesGroup

        authorize :update_virtual_registry_setting
        authorize_granular_token permissions: :update_virtual_registry_setting,
          boundary_argument: :full_path, boundary_type: :group

        argument :full_path,
          GraphQL::Types::ID,
          required: true,
          description: 'Group path for the group virtual registries.'

        argument :enabled,
          GraphQL::Types::Boolean,
          required: false,
          description: 'Enable or disable the virtual registries.'

        field :virtual_registries_setting,
          ::Types::VirtualRegistries::SettingType,
          null: true,
          description: 'Virtual registries settings after mutation.'

        def resolve(full_path:, **args)
          group = authorized_find!(full_path:)

          raise_resource_not_available_error! unless virtual_registries_enabled?(group)

          result = ::VirtualRegistries::Settings::CreateOrUpdateService
            .new(group: group, current_user: current_user, params: args)
            .execute

          {
            virtual_registries_setting: result.payload[:virtual_registries_setting],
            errors: result.errors
          }
        end

        private

        def find_object(full_path:)
          resolve_group(full_path:)
        end

        def authorized_resource?(group)
          return false if group.nil?

          Ability.allowed?(current_user, :update_virtual_registry_setting, group.virtual_registry_policy_subject)
        end

        def virtual_registries_enabled?(group)
          ::Feature.enabled?(:maven_virtual_registry, group) &&
            group.licensed_feature_available?(:packages_virtual_registry)
        end
      end
    end
  end
end
