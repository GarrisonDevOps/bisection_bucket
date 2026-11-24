# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Container
      module Registry
        module Upstream
          class Destroy < ::Mutations::VirtualRegistries::Registry::Upstream::Destroy
            graphql_name 'ContainerVirtualRegistryUpstreamDelete'

            authorize_granular_token permissions: :disassociate_container_virtual_registry_upstream,
              boundary_argument: :upstream_id, boundary: :group, boundary_type: :group

            argument :upstream_id, ::Types::GlobalIDType[::VirtualRegistries::Container::RegistryUpstream],
              required: true,
              description: 'ID of the container virtual registry upstream.'

            field :registry_upstream,
              ::Types::VirtualRegistries::Container::RegistryUpstreamWithRegistryType,
              null: true,
              description: 'Deleted container registry upstream.'

            private

            def service_class
              ::VirtualRegistries::Container::DestroyRegistryUpstreamService
            end
          end
        end
      end
    end
  end
end
