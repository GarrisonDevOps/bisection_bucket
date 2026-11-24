# frozen_string_literal: true

module Types
  module DependencyProxy
    module Packages
      class SettingType < ::Types::BaseObject
        graphql_name 'DependencyProxyPackagesSetting'

        description 'Project-level Dependency Proxy for packages settings'

        authorize :admin_dependency_proxy_packages_settings

        field :enabled,
          GraphQL::Types::Boolean,
          null: false,
          description: 'Indicates whether the dependency proxy for packages is enabled for the project.'

        field :maven_external_registry_url,
          GraphQL::Types::String,
          null: true,
          description: 'URL for the external Maven packages registry.'

        field :maven_external_registry_username,
          GraphQL::Types::String,
          null: true,
          description: 'Username for the external Maven packages registry.'
      end
    end
  end
end
