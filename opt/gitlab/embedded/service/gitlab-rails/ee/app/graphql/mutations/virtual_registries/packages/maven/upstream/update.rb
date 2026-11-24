# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Packages
      module Maven
        module Upstream
          class Update < BaseMutation
            graphql_name 'MavenUpstreamUpdate'

            authorize :update_virtual_registry
            authorize_granular_token permissions: :update_maven_virtual_registry_upstream,
              boundary_argument: :id, boundary: :group, boundary_type: :group

            argument :id, ::Types::GlobalIDType[::VirtualRegistries::Packages::Maven::Upstream],
              required: true,
              description: 'ID of the upstream registry.'

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

            argument :metadata_cache_validity_hours, GraphQL::Types::Int,
              required: false,
              description: 'Metadata cache validity period.'

            argument :username, GraphQL::Types::String,
              required: false,
              description: 'Username of the upstream registry.'

            argument :password, GraphQL::Types::String,
              required: false,
              description: 'Password of the upstream registry.'

            field :upstream,
              ::Types::VirtualRegistries::Packages::Maven::UpstreamDetailsType,
              null: true,
              description: 'Maven upstream after the mutation.'

            def resolve(id:, **args)
              upstream = authorized_find!(id: id)

              raise_resource_not_available_error! unless virtual_registries_enabled?(upstream.group)

              result = ::VirtualRegistries::Packages::Maven::Upstreams::UpdateService
                .new(upstream: upstream, current_user: current_user, params: args)
                .execute

              {
                upstream: result.success? ? result.payload : nil,
                errors: result.errors
              }
            end

            def virtual_registries_enabled?(group)
              ::VirtualRegistries::Packages::Maven.feature_enabled?(group)
            end
          end
        end
      end
    end
  end
end
