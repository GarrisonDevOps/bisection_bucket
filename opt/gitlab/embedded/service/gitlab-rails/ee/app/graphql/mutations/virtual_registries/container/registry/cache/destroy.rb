# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Container
      module Registry
        module Cache
          class Destroy < ::Mutations::VirtualRegistries::Container::Cache::Destroy
            graphql_name 'ContainerVirtualRegistryCacheDelete'

            authorize_granular_token permissions: :purge_container_virtual_registry_cache,
              boundary_argument: :id, boundary: :group, boundary_type: :group

            argument :id, ::Types::GlobalIDType[::VirtualRegistries::Container::Registry],
              required: true,
              description: 'ID of the container virtual registry.'

            field :registry,
              ::Types::VirtualRegistries::Container::RegistryType,
              null: true,
              description: 'Container virtual registry.'

            private

            def response_field_name
              :registry
            end
          end
        end
      end
    end
  end
end
