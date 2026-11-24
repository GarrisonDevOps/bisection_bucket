# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Container
      module Registry
        class Destroy < ::Mutations::VirtualRegistries::Registry::Destroy
          graphql_name 'ContainerVirtualRegistryDelete'

          authorize_granular_token permissions: :delete_container_virtual_registry,
            boundary_argument: :id, boundary: :group, boundary_type: :group

          argument :id, ::Types::GlobalIDType[::VirtualRegistries::Container::Registry],
            required: true,
            description: 'ID of the container virtual registry to be deleted.'

          field :registry,
            ::Types::VirtualRegistries::Container::RegistryType,
            null: true,
            description: 'Deleted container virtual registry.'

          private

          def available?(registry)
            ::VirtualRegistries::Container.virtual_registry_available?(
              registry.group, current_user, :destroy_virtual_registry
            )
          end
        end
      end
    end
  end
end
