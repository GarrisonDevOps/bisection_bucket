# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Container
      module Upstream
        class Test < ::Mutations::VirtualRegistries::Upstream::Test
          graphql_name 'ContainerUpstreamTest'

          # These boundaries are ORed. They stay aligned with the resolution
          # order of `find_upstream` (`id` wins over `group_path`) because the
          # base mutation's `authorized?` drops `group_path` when `id` is
          # given, so only the boundary of the argument that resolves the
          # upstream can satisfy the check.
          authorize_granular_token permissions: :test_container_virtual_registry_upstream,
            boundaries: [
              { boundary_argument: :id, boundary: :group, boundary_type: :group },
              { boundary_argument: :group_path, boundary_type: :group }
            ]

          argument :id, ::Types::GlobalIDType[::VirtualRegistries::Container::Upstream],
            required: false,
            description: 'ID of the upstream registry to test. ' \
              'When provided, `groupPath`, `url`, `username`, and `password` are ignored.'

          private

          def available?(group)
            ::VirtualRegistries::Container.virtual_registry_available?(group, current_user)
          end

          def upstream_class
            ::VirtualRegistries::Container::Upstream
          end
        end
      end
    end
  end
end
