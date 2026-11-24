# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class ManifestResolver < BaseResolver
      include ::ArtifactRegistry::ResolvesOnRepository

      # Bounds aliased re-selection: a second `manifest` selection in one operation raises rather
      # than issuing another Artifact Registry request. Keyed per field, so it does not bound the
      # operation's total fan-out across the other AR fields (see gitlab-org/gitlab#624954).
      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

      type ::Types::ArtifactRegistry::ManifestDetailsType, null: true

      # AR-native identifier of the image the manifest belongs to, not a GitLab global ID: the
      # route carries it verbatim and the client passes it straight to AR, so a GlobalIDType would
      # reject the value the caller holds.
      # No experiment marker: the argument is required, and GraphQL implements experiment through
      # the deprecation mechanism, which cannot apply to a required argument. The sibling image and
      # version resolvers leave their required IDs unmarked for the same reason.
      argument :artifact_id, GraphQL::Types::ID, # rubocop:disable Graphql/IDType -- AR-native ID, not a GitLab global ID
        required: true,
        description: 'ID of the image the manifest belongs to, in Artifact Registry.'

      # The full sha256:<hex> digest, not the short digest and not an opaque element id: it is how
      # Artifact Registry addresses a manifest, and the route carries it verbatim.
      argument :digest, GraphQL::Types::String,
        required: true,
        description: 'Digest of the manifest in Artifact Registry.'

      private

      def resolve_artifact_registry(artifact_id:, digest:)
        # Client#manifest raises on a package repository; holding the format resolves null with no
        # request instead, honoring the silent null the field promises.
        return unless presented_repository.images?

        manifest = artifact_registry_client.manifest(
          slug: artifact_registry_slug,
          repository_name: presented_repository.name,
          format: presented_repository.format,
          image_id: artifact_id,
          digest: digest
        )

        return unless manifest

        # Carries the image id alongside the repository so the referrers connection mounted on the
        # detail type can re-issue its own read, which is keyed on the image id and the digest pair.
        ::ArtifactRegistry::ManifestPresenter.new(manifest, repository: presented_repository, image_id: artifact_id)
      end
    end
  end
end
