# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Container
      module Registry
        class Create < ::Mutations::VirtualRegistries::Registry::Create
          graphql_name 'ContainerVirtualRegistryCreate'

          authorize_granular_token permissions: :create_container_virtual_registry,
            boundary_argument: :group_path, boundary_type: :group

          field :registry,
            ::Types::VirtualRegistries::Container::RegistryType,
            null: true,
            description: 'Container virtual registry after the mutation.'

          private

          def service_class
            ::VirtualRegistries::Container::CreateRegistryService
          end
        end
      end
    end
  end
end
