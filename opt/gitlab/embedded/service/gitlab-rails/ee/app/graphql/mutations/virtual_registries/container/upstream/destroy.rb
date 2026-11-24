# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Container
      module Upstream
        class Destroy < ::Mutations::VirtualRegistries::Upstream::Destroy
          graphql_name 'ContainerUpstreamDelete'

          authorize_granular_token permissions: :delete_container_virtual_registry_upstream,
            boundary_argument: :id, boundary: :group, boundary_type: :group

          argument :id, ::Types::GlobalIDType[::VirtualRegistries::Container::Upstream],
            required: true,
            description: 'ID of the upstream to be deleted.'

          field :upstream,
            ::Types::VirtualRegistries::Container::UpstreamDetailsType,
            null: true,
            description: 'Destroyed upstream.'

          private

          def service_class
            ::VirtualRegistries::Container::DestroyUpstreamService
          end
        end
      end
    end
  end
end
