# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Packages
      module Maven
        class RegistryUpstreamWithRegistryType < ::Types::BaseObject
          graphql_name 'MavenRegistryUpstreamWithRegistry'
          description 'Represents a Maven virtual registry upstream and its relationship to the registry.'

          authorize :read_virtual_registry

          implements Types::VirtualRegistries::RegistryUpstreamInterface

          field :registry, ::Types::VirtualRegistries::Packages::Maven::RegistryType, null: false,
            description: 'Maven registry associated with the registry upstream.',
            experiment: { milestone: '18.6' }

          def registry
            Gitlab::Graphql::Loaders::BatchModelLoader.new(
              ::VirtualRegistries::Packages::Maven::Registry,
              object.registry_id
            ).find
          end
        end
      end
    end
  end
end
