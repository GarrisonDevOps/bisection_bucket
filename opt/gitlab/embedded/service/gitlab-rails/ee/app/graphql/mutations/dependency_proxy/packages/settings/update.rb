# frozen_string_literal: true

module Mutations
  module DependencyProxy
    module Packages
      module Settings
        class Update < ::Mutations::BaseMutation
          graphql_name 'UpdateDependencyProxyPackagesSettings'

          include ::ResolvesProject

          description <<~DESC.chomp
            Updates or creates dependency proxy for packages settings.
            Requires the packages and dependency proxy to be enabled in the config.
            Requires the packages feature to be enabled at the project level.
          DESC

          authorize :admin_dependency_proxy_packages_settings
          authorize_granular_token permissions: :update_dependency_proxy_packages_setting,
            boundary_argument: :project_path, boundary_type: :project

          argument :project_path,
            GraphQL::Types::ID,
            required: true,
            description: 'Project path for the dependency proxy for packages settings.'

          argument :enabled,
            GraphQL::Types::Boolean,
            required: false,
            description: copy_field_description(::Types::DependencyProxy::Packages::SettingType, :enabled)

          argument :maven_external_registry_url,
            GraphQL::Types::String,
            required: false,
            description: copy_field_description(
              ::Types::DependencyProxy::Packages::SettingType,
              :maven_external_registry_url
            )

          argument :maven_external_registry_username,
            GraphQL::Types::String,
            required: false,
            description: copy_field_description(
              ::Types::DependencyProxy::Packages::SettingType,
              :maven_external_registry_username
            )

          argument :maven_external_registry_password,
            GraphQL::Types::String,
            required: false,
            description: 'Password for the external Maven packages registry. ' \
                         'Introduced in 16.5: This feature is an Experiment. ' \
                         'It can be changed or removed at any time.'

          field :dependency_proxy_packages_setting,
            ::Types::DependencyProxy::Packages::SettingType,
            null: true,
            description: 'Dependency proxy for packages settings after mutation.'

          def resolve(project_path:, **args)
            setting = authorized_find!(project_path: project_path)

            result = ::DependencyProxy::Packages::Settings::UpdateService
              .new(setting: setting, current_user: current_user, params: args)
              .execute

            {
              dependency_proxy_packages_setting: result.payload[:dependency_proxy_packages_setting],
              errors: result.errors
            }
          end

          private

          def find_object(project_path:)
            resolve_project(full_path: project_path).sync&.dependency_proxy_packages_setting
          end
        end
      end
    end
  end
end
