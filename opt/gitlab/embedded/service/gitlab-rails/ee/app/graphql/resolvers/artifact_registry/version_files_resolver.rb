# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class VersionFilesResolver < BaseResolver
      include ::ArtifactRegistry::PaginatesLists

      # Bounds aliased re-selection: a second `files` selection in one operation raises rather
      # than issuing another Artifact Registry request. Keyed per field definition, so Step 5's
      # limit on `version` does not cover this one -- it needs its own.
      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

      type ::Types::ArtifactRegistry::VersionFileType.connection_type, null: true

      private

      def resolve_artifact_registry(first: nil, last: nil, before: nil, after: nil)
        page = artifact_registry_client.version_files(
          slug: artifact_registry_slug,
          repository_name: presented_repository.name,
          format: presented_repository.format,
          version_id: presented_version.id,
          **artifact_registry_pagination(first: first, last: last, before: before, after: after)
        )

        return unless page

        artifact_registry_connection(page)
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
