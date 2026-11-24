# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Container
      class RegistryDetailsType < ::Types::BaseObject
        graphql_name 'ContainerRegistryDetails'
        description 'Represents container virtual registry details'

        authorize :read_virtual_registry

        implements Types::VirtualRegistries::RegistryInterface

        field :registry_upstreams,
          [::Types::VirtualRegistries::Container::RegistryUpstreamWithUpstreamType],
          null: false,
          description: 'List of registry upstreams for the container virtual registry.',
          experiment: { milestone: '18.7' }
      end
    end
  end
end
