# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Packages
      module Maven
        module Upstream
          module Cache
            class Destroy < ::Mutations::VirtualRegistries::Packages::Maven::Cache::Destroy
              graphql_name 'MavenUpstreamCacheDelete'

              authorize_granular_token permissions: :purge_maven_virtual_registry_upstream_cache,
                boundary_argument: :id, boundary: :group, boundary_type: :group

              argument :id, ::Types::GlobalIDType[::VirtualRegistries::Packages::Maven::Upstream],
                required: true,
                description: 'ID of the Maven virtual registry upstream.'

              field :upstream,
                ::Types::VirtualRegistries::Packages::Maven::UpstreamDetailsType,
                null: true,
                description: 'Maven virtual registry upstream.'

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
end
