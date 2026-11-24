# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Packages
      module Maven
        module Registry
          class Update < ::Mutations::VirtualRegistries::Registry::Update
            graphql_name 'MavenVirtualRegistryUpdate'

            authorize_granular_token permissions: :update_maven_virtual_registry,
              boundary_argument: :id, boundary: :group, boundary_type: :group

            argument :id, ::Types::GlobalIDType[::VirtualRegistries::Packages::Maven::Registry],
              required: true,
              description: 'ID of the Maven virtual registry to be updated.'

            field :registry,
              ::Types::VirtualRegistries::Packages::Maven::RegistryType,
              null: true,
              description: 'Maven virtual registry after the mutation.'

            private

            def service_class
              ::VirtualRegistries::Packages::Maven::UpdateRegistryService
            end

            def virtual_registry_available?(group)
              ::VirtualRegistries::Packages::Maven.feature_enabled?(group)
            end
          end
        end
      end
    end
  end
end
