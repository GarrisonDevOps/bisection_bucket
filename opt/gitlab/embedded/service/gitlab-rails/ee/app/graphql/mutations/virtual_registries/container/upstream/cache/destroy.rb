# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Container
      module Upstream
        module Cache
          class Destroy < ::Mutations::VirtualRegistries::Container::Cache::Destroy
            graphql_name 'ContainerUpstreamCacheDelete'

            authorize_granular_token permissions: :purge_container_virtual_registry_upstream_cache,
              boundary_argument: :id, boundary: :group, boundary_type: :group

            argument :id, ::Types::GlobalIDType[::VirtualRegistries::Container::Upstream],
              required: true,
              description: 'ID of the container virtual registry upstream.'

            field :upstream,
              ::Types::VirtualRegistries::Container::UpstreamType,
              null: true,
              description: 'Container virtual registry upstream.'

            private

            def response_field_name
              :upstream
            end
          end
        end
      end
    end
  end
end
