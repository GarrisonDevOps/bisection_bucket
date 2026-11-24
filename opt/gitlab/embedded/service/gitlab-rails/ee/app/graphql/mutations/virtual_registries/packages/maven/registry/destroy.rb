# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Packages
      module Maven
        module Registry
          class Destroy < ::Mutations::VirtualRegistries::Registry::Destroy
            graphql_name 'MavenVirtualRegistryDelete'

            authorize_granular_token permissions: :delete_maven_virtual_registry,
              boundary_argument: :id, boundary: :group, boundary_type: :group

            argument :id, ::Types::GlobalIDType[::VirtualRegistries::Packages::Maven::Registry],
              required: true,
              description: 'ID of the Maven virtual registry to be deleted.'

            field :registry,
              ::Types::VirtualRegistries::Packages::Maven::RegistryType,
              null: true,
              description: 'Deleted Maven virtual registry.'

            private

            def available?(registry)
              ::VirtualRegistries::Packages::Maven.virtual_registry_available?(
                registry.group, current_user, :destroy_virtual_registry
              )
            end
          end
        end
      end
    end
  end
end
