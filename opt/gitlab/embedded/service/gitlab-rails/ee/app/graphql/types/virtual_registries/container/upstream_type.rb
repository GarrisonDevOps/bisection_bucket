# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Container
      class UpstreamType < ::Types::BaseObject
        graphql_name 'ContainerUpstream'
        description 'Represents a container upstream registry.'

        authorize :read_virtual_registry
        connection_type_class ::Types::CountableConnectionType

        implements Types::VirtualRegistries::UpstreamInterface

        field :username, GraphQL::Types::String, null: true,
          authorize: :update_virtual_registry,
          description: 'Username to sign in to the upstream registry.',
          experiment: { milestone: '18.7' }

        def registries_count
          BatchLoader::GraphQL.for(object.id)
            .batch(key: 'vregs-container-upstreams-registries-count') do |upstream_ids, loader|
            counts = ::VirtualRegistries::Container::RegistryUpstream
              .registries_count_by_upstream_ids(upstream_ids)

            upstream_ids.each { |id| loader.call(id, counts[id] || 0) }
          end
        end
      end
    end
  end
end
