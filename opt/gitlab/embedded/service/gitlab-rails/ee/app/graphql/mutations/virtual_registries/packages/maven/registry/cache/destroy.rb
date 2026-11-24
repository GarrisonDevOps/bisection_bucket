# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Packages
      module Maven
        module Registry
          module Cache
            class Destroy < ::Mutations::VirtualRegistries::Packages::Maven::Cache::Destroy
              graphql_name 'MavenVirtualRegistryCacheDelete'

              authorize_granular_token permissions: :purge_maven_virtual_registry_cache,
                boundary_argument: :id, boundary: :group, boundary_type: :group

              argument :id, ::Types::GlobalIDType[::VirtualRegistries::Packages::Maven::Registry],
                required: true,
                description: 'ID of the Maven virtual registry.'

              field :registry,
                ::Types::VirtualRegistries::Packages::Maven::RegistryType,
                null: true,
                description: 'Maven virtual registry.'

              private

              def response_field_name
                :registry
              end
            end
          end
        end
      end
    end
  end
end
