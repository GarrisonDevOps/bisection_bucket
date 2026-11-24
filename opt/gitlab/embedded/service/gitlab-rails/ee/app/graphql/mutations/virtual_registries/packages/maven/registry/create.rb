# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Packages
      module Maven
        module Registry
          class Create < ::Mutations::VirtualRegistries::Registry::Create
            graphql_name 'MavenVirtualRegistryCreate'

            authorize_granular_token permissions: :create_maven_virtual_registry,
              boundary_argument: :group_path, boundary_type: :group

            field :registry,
              ::Types::VirtualRegistries::Packages::Maven::RegistryType,
              null: true,
              description: 'Maven virtual registry after the mutation.'

            private

            def service_class
              ::VirtualRegistries::Packages::Maven::CreateRegistryService
            end
          end
        end
      end
    end
  end
end
