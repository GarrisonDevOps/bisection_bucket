# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Container
      class RegistryUpstreamWithRegistryType < ::Types::BaseObject
        graphql_name 'ContainerRegistryUpstreamWithRegistry'
        description 'Represents a container registry upstream and its registry.'

        authorize :read_virtual_registry

        implements Types::VirtualRegistries::RegistryUpstreamInterface

        field :registry, ::Types::VirtualRegistries::Container::RegistryType, null: false,
          description: 'Container registry associated with the upstream registry.',
          experiment: { milestone: '18.8' }

        def registry
          Gitlab::Graphql::Loaders::BatchModelLoader.new(
            ::VirtualRegistries::Container::Registry,
            object.registry_id
          ).find
        end
      end
    end
  end
end
