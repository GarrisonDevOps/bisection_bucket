# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Packages
      module Maven
        class RegistryDetailsType < ::Types::BaseObject
          graphql_name 'MavenRegistryDetails'
          description 'Represents Maven virtual registry details'

          authorize :read_virtual_registry

          implements Types::VirtualRegistries::RegistryInterface

          field :registry_upstreams,
            [::Types::VirtualRegistries::Packages::Maven::RegistryUpstreamWithUpstreamType],
            null: false,
            description: 'List of registry upstreams for the Maven virtual registry.',
            experiment: { milestone: '18.7' }
        end
      end
    end
  end
end
