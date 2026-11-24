# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Container
      module Registry
        module Upstream
          class Create < ::Mutations::VirtualRegistries::Registry::Upstream::Create
            graphql_name 'ContainerVirtualRegistryUpstreamCreate'

            authorize_granular_token permissions: :associate_container_virtual_registry_upstream,
              boundary_argument: :registry_id, boundary: :group, boundary_type: :group

            argument :registry_id, ::Types::GlobalIDType[::VirtualRegistries::Container::Registry],
              required: true,
              description: 'ID of the container virtual registry.'

            argument :upstream_id, ::Types::GlobalIDType[::VirtualRegistries::Container::Upstream],
              required: true,
              description: 'ID of the upstream.'

            field :registry_upstream,
              ::Types::VirtualRegistries::Container::RegistryUpstreamWithRegistryType,
              null: true,
              description: 'Container registry upstream after association.'

            private

            def service_class
              ::VirtualRegistries::Container::CreateRegistryUpstreamService
            end
          end
        end
      end
    end
  end
end
