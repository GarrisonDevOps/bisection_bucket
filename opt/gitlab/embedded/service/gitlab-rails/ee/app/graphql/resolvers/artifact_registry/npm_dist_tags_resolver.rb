# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class NpmDistTagsResolver < BaseResolver
      include ::ArtifactRegistry::PaginatesLists

      # Bounds aliased re-selection per field (see gitlab-org/gitlab#624954).
      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

      type ::Types::ArtifactRegistry::NpmDistTagType.connection_type, null: true

      # Artifact Registry holds a remote repository's dist-tags as an opaque document rather than
      # rows and answers 404, so this refuses it ahead of the call, matching the delete mutation.
      REMOTE_KIND = 'remote'

      private

      def resolve_artifact_registry(first: nil, last: nil, before: nil, after: nil)
        return unless presented_repository.npm?
        return if presented_repository.kind == REMOTE_KIND

        page = artifact_registry_client.npm_dist_tags(
          slug: artifact_registry_slug,
          repository_name: presented_repository.name,
          package_id: presented_artifact.id,
          **artifact_registry_pagination(first: first, last: last, before: before, after: after)
        )

        # A package removed between the two reads resolves the connection null rather than erroring.
        return unless page

        artifact_registry_connection(page)
      end

      # The connection hangs off a package element, not the organization the base resolver reads.
      def artifact_registry_organization
        presented_artifact.organization
      end

      def presented_repository
        presented_artifact.repository
      end

      # `Resolvers::BaseResolver#object` unwraps the presenter to its subject value object,
      # dropping the repository and organization. Reads go through `@object` instead.
      def presented_artifact
        @object
      end
    end
  end
end
