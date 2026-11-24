# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class ManifestReferrersResolver < BaseResolver
      include ::ArtifactRegistry::PaginatesLists

      # Bounds aliased re-selection: a second `referrers` selection in one operation raises rather
      # than issuing another Artifact Registry request. Keyed per field definition, so the parent
      # `manifest` field's own limit does not cover this one -- it needs its own.
      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

      # Returns the list element type unwidened: a referrer is an ordinary manifest, and the three
      # fields the referrers table renders are already among the seven ManifestType carries.
      type ::Types::ArtifactRegistry::ManifestType.connection_type, null: true

      private

      def resolve_artifact_registry(first: nil, last: nil, before: nil, after: nil)
        page = artifact_registry_client.manifest_referrers(
          slug: artifact_registry_slug,
          repository_name: presented_repository.name,
          format: presented_repository.format,
          image_id: presented_manifest.image_id,
          digest: presented_manifest.digest,
          **artifact_registry_pagination(first: first, last: last, before: before, after: after)
        )

        # A manifest deleted between the two reads resolves the connection null rather than
        # erroring; a remote repository's contractually-empty list resolves to an empty connection.
        return unless page

        artifact_registry_connection(page)
      end

      # The connection hangs off the manifest detail element, not the organization the base
      # resolver reads, so both the client acquisition and the slug resolve through the
      # presenter's organization.
      def artifact_registry_organization
        presented_manifest.organization
      end

      def presented_repository
        presented_manifest.repository
      end

      # `Resolvers::BaseResolver#object` unwraps the presenter to its subject value object,
      # dropping the repository, organization, and image id. Every read here goes through `@object`
      # instead, so the manifest presenter's context stays reachable.
      def presented_manifest
        @object
      end
    end
  end
end
