# frozen_string_literal: true

module Resolvers
  module Cd
    class VersionEnvironmentsResolver < BaseResolver
      type ::Types::Cd::EnvironmentType.connection_type, null: true

      alias_method :version, :object

      # Batched via Cd::Version.environments_for so that resolving `environments`
      # for a page of versions executes a small, fixed number of queries
      # (one per distinct service among the requested versions) instead of one
      # query per version.
      def resolve
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        BatchLoader::GraphQL.for(version).batch do |versions, loader|
          environments_by_version_id = ::Cd::Version.environments_for(versions)

          versions.each do |v|
            loader.call(v, environments_by_version_id[v.id] || [])
          end
        end
      end
    end
  end
end
