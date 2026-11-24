# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Container
      class UpstreamDetailsType < ::Types::VirtualRegistries::Container::UpstreamType
        graphql_name 'ContainerUpstreamDetails'
        description 'Represents container upstream details.'

        authorize :read_virtual_registry

        field :registry_upstreams,
          [::Types::VirtualRegistries::Container::RegistryUpstreamWithRegistryType],
          null: false,
          description: 'Represents the connected upstream registry for an upstream ' \
            'and the upstream position data.',
          experiment: { milestone: '18.8' }

        field :cache_entries,
          ::Types::VirtualRegistries::Container::Cache::EntryType.connection_type,
          null: true,
          description: 'Represents cache entries for the upstream container registry.',
          resolver: ::Resolvers::VirtualRegistries::Container::Cache::EntriesResolver,
          experiment: { milestone: '18.9' }
      end
    end
  end
end
