# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class VersionStatisticsResolver < BaseResolver
      # Bounds aliased re-selection: a second `statistics` selection in one operation raises rather
      # than issuing another Artifact Registry request. Keyed per field definition, so it needs its
      # own limit separate from the version and files fields.
      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

      type ::Types::ArtifactRegistry::VersionStatisticsType, null: true

      # Artifact Registry answers 404 for statistics on virtual and remote repositories.
      HOSTED_KIND = 'hosted'

      private

      def resolve_artifact_registry
        return unless presented_repository.packages?
        return unless presented_repository.kind == HOSTED_KIND

        artifact_registry_client.version_statistics(
          slug: artifact_registry_slug,
          repository_name: presented_repository.name,
          format: presented_repository.format,
          version_id: presented_version.id
        )
      end

      def artifact_registry_organization
        presented_version.organization
      end

      def presented_repository
        presented_version.repository
      end

      def presented_version
        @object
      end
    end
  end
end
