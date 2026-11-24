# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Container
      module Upstream
        class Create < BaseMutation
          graphql_name 'ContainerUpstreamCreate'

          authorize :create_virtual_registry
          authorize_granular_token permissions: :create_container_virtual_registry_upstream,
            boundary_argument: :id, boundary: :group, boundary_type: :group

          argument :id, ::Types::GlobalIDType[::VirtualRegistries::Container::Registry],
            required: true,
            description: 'ID of the upstream registry.'

          argument :name, GraphQL::Types::String,
            required: true,
            description: 'Name of upstream registry.'

          argument :description, GraphQL::Types::String,
            required: false,
            description: 'Description of the upstream registry.'

          argument :url, GraphQL::Types::String,
            required: true,
            description: 'URL of the upstream registry.'

          argument :cache_validity_hours, GraphQL::Types::Int,
            required: false,
            default_value: 24,
            description: 'Cache validity period. Defaults to 24 hours.'

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
            registry = authorized_find!(id: id)

            raise_resource_not_available_error! unless ::VirtualRegistries::Container.virtual_registry_available?(
              registry.group, current_user)

            service_response = ::VirtualRegistries::CreateUpstreamService
                                  .new(registry: registry, current_user: current_user, params: args)
                                  .execute

            {
              upstream: service_response.success? ? service_response.payload : nil,
              errors: service_response.errors
            }
          end
        end
      end
    end
  end
end
