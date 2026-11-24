# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class PackagesResolver < BaseResolver
      include ::ArtifactRegistry::PaginatesLists
      include ::ArtifactRegistry::ResolvesOnRepository

      # Bounds aliased re-selection: a second `packages` selection in one operation raises rather
      # than issuing another Artifact Registry request. Keyed per field, so it does not bound the
      # operation's total fan-out across the other AR fields (see gitlab-org/gitlab#624954).
      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

      type ::Types::ArtifactRegistry::PackageType.connection_type, null: true

      private

      def resolve_artifact_registry(first: nil, last: nil, before: nil, after: nil)
        return if presented_repository.virtual?

        # The client rejects a non-package format before issuing a request, so a container
        # repository would raise rather than earn the 404 that resolves this connection null.
        return unless presented_repository.packages?

        page = artifact_registry_client.packages(
          slug: artifact_registry_slug,
          repository_name: presented_repository.name,
          format: presented_repository.format,
          **artifact_registry_pagination(first: first, last: last, before: before, after: after)
        )

        # A repository deleted between the two reads resolves null rather than erroring.
        return unless page

        artifact_registry_connection(page, nodes: page.nodes.map { |node| wrap_in_artifact_presenter(node) })
      end
    end
  end
end
