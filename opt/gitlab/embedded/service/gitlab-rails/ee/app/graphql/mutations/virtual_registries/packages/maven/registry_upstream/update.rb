# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Packages
      module Maven
        module RegistryUpstream
          class Update < ::Mutations::VirtualRegistries::RegistryUpstream::Update
            graphql_name 'MavenVirtualRegistryUpstreamUpdate'

            authorize_granular_token permissions: :update_maven_virtual_registry_upstream,
              boundary_argument: :id, boundary: :group, boundary_type: :group

            argument :id, ::Types::GlobalIDType[::VirtualRegistries::Packages::Maven::RegistryUpstream],
              required: true,
              description: 'ID of the Maven virtual registry upstream.'

            field :registry_upstream,
              ::Types::VirtualRegistries::Packages::Maven::RegistryUpstreamWithRegistryType,
              null: true,
              description: 'Maven registry upstream after update.'

            private

            def enabled?(registry_upstream)
              ::VirtualRegistries::Packages::Maven.feature_enabled?(registry_upstream.group)
            end
          end
        end
      end
    end
  end
end
