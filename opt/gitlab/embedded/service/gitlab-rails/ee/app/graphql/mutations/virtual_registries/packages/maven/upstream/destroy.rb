# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Packages
      module Maven
        module Upstream
          class Destroy < ::Mutations::VirtualRegistries::Upstream::Destroy
            graphql_name 'MavenUpstreamDelete'

            authorize_granular_token permissions: :delete_maven_virtual_registry_upstream,
              boundary_argument: :id, boundary: :group, boundary_type: :group

            argument :id, ::Types::GlobalIDType[::VirtualRegistries::Packages::Maven::Upstream],
              required: true,
              description: 'ID of the upstream to be deleted.'

            field :upstream, ::Types::VirtualRegistries::Packages::Maven::UpstreamDetailsType,
              null: true,
              description: 'Destroyed upstream.'

            private

            def service_class
              ::VirtualRegistries::Packages::Maven::DestroyUpstreamService
            end
          end
        end
      end
    end
  end
end
