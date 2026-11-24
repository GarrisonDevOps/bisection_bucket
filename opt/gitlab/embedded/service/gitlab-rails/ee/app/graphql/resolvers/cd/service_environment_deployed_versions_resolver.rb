# frozen_string_literal: true

module Resolvers
  module Cd
    class ServiceEnvironmentDeployedVersionsResolver < BaseResolver
      type ::Types::Cd::VersionType.connection_type, null: true

      max_page_size 20

      alias_method :service_environment_health, :object

      # Batched via Cd::Version.for_service_environments so that resolving
      # `deployedVersions` for a page of serviceEnvironmentHealths rows executes a
      # small, fixed number of queries (per distinct service among the requested
      # rows) instead of one query per row.
      def resolve
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        BatchLoader::GraphQL.for(service_environment_health).batch do |healths, loader|
          versions_by_pair = ::Cd::Version.for_service_environments(healths)

          healths.each do |health|
            loader.call(health, versions_by_pair[[health.service_id, health.environment_id]] || [])
          end
        end
      end
    end
  end
end
