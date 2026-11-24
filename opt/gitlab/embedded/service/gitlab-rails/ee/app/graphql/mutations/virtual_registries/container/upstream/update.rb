# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Container
      module Upstream
        class Update < BaseMutation
          graphql_name 'ContainerUpstreamUpdate'

          authorize :update_virtual_registry
          authorize_granular_token permissions: :update_container_virtual_registry_upstream,
            boundary_argument: :id, boundary: :group, boundary_type: :group

          argument :id, ::Types::GlobalIDType[::VirtualRegistries::Container::Upstream],
            required: true,
            description: 'ID of the container virtual registry upstream.'

          argument :name, GraphQL::Types::String,
            required: false,
            description: 'Name of upstream registry.'

          argument :description, GraphQL::Types::String,
            required: false,
            description: 'Description of the upstream registry.'

          argument :url, GraphQL::Types::String,
            required: false,
            description: 'URL of the upstream registry.'

          argument :cache_validity_hours, GraphQL::Types::Int,
            required: false,
            description: 'Cache validity period.'

          argument :username, GraphQL::Types::String,
            required: false,
            description: 'Username of the upstream registry.'

          argument :password, GraphQL::Types::String,
            required: false,
            description: 'Password of the upstream registry.'

          field :upstream,
            ::Types::VirtualRegistries::Container::UpstreamDetailsType,
            null: true,
            description: 'Container upstream after the mutation.'

          def resolve(id:, **args)
            upstream = authorized_find!(id: id)

            raise_resource_not_available_error! unless virtual_registries_enabled?(upstream.group)

            result = ::VirtualRegistries::Container::UpdateUpstreamService
              .new(upstream: upstream, current_user: current_user, params: args)
              .execute

            {
              upstream: result.success? ? result.payload : nil,
              errors: result.errors
            }
          end

          private

          def virtual_registries_enabled?(group)
            ::VirtualRegistries::Container.virtual_registry_available?(group, current_user)
          end
        end
      end
    end
  end
end
