# frozen_string_literal: true

module Mutations
  module Security
    module CiConfiguration
      class SetContainerScanningForRegistry < BaseMutation
        graphql_name 'SetContainerScanningForRegistry'

        include FindsNamespace

        description <<~DESC
          Enable/disable container scanning for registry for the given project.
        DESC

        argument :namespace_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the namespace (project).'

        argument :enable, GraphQL::Types::Boolean,
          required: true,
          description: 'Desired status for container scanning for registry feature.'

        field :container_scanning_for_registry_enabled, GraphQL::Types::Boolean,
          null: true,
          description: 'Whether the feature is enabled.'

        authorize :enable_container_scanning_for_registry

        authorize_granular_token permissions: :update_security_setting,
          boundary_argument: :namespace_path, boundary_type: :project

        def resolve(namespace_path:, enable:)
          namespace = find_namespace(namespace_path)
          raise_resource_not_available_error! if namespace.self_or_ancestors_archived?

          response = ::Security::Configuration::SetContainerScanningForRegistryService
            .execute(namespace: namespace, enable: enable)

          { container_scanning_for_registry_enabled: response.payload[:enabled], errors: response.errors }
        end

        private

        def find_namespace(namespace_path)
          namespace = authorized_find!(namespace_path)
          # This will be removed following the completion of https://gitlab.com/gitlab-org/gitlab/-/issues/451430
          unless namespace.is_a? Project
            raise_resource_not_available_error! 'Setting only available for Project namespaces.'
          end

          namespace
        end
      end
    end
  end
end
