# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Container
      class RegistryUpstreamWithUpstreamType < ::Types::BaseObject
        graphql_name 'ContainerRegistryUpstreamWithUpstream'
        description 'Represents a container virtual registry upstream and its relationship to the upstream.'

        authorize :read_virtual_registry

        implements Types::VirtualRegistries::RegistryUpstreamInterface

        field :upstream, ::Types::VirtualRegistries::Container::UpstreamType, null: false,
          description: 'Container upstream associated with the registry upstream.',
          experiment: { milestone: '18.7' }

        def upstream
          Gitlab::Graphql::Loaders::BatchModelLoader.new(
            ::VirtualRegistries::Container::Upstream,
            object.upstream_id
          ).find
        end
      end
    end
  end
end
