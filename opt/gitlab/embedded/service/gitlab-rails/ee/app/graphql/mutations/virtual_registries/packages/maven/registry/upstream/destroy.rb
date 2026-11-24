# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Packages
      module Maven
        module Registry
          module Upstream
            class Destroy < ::Mutations::VirtualRegistries::Registry::Upstream::Destroy
              graphql_name 'MavenVirtualRegistryUpstreamDelete'

              authorize_granular_token permissions: :disassociate_maven_virtual_registry_upstream,
                boundary_argument: :upstream_id, boundary: :group, boundary_type: :group

              argument :upstream_id,
                ::Types::GlobalIDType[::VirtualRegistries::Packages::Maven::RegistryUpstream],
                required: true,
                description: 'ID of the Maven virtual registry upstream.'

              field :registry_upstream,
                ::Types::VirtualRegistries::Packages::Maven::RegistryUpstreamWithRegistryType,
                null: true,
                description: 'Deleted maven registry upstream.'

              private

              def service_class
                ::VirtualRegistries::Packages::Maven::DestroyRegistryUpstreamService
              end
            end
          end
        end
      end
    end
  end
end
