# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class PackageResolver < BaseResolver
      include ::ArtifactRegistry::ResolvesOnRepository

      # Bounds aliased re-selection: a second `package` selection in one operation raises rather
      # than issuing another Artifact Registry request. Keyed per field, so it does not bound the
      # operation's total fan-out across the other AR fields (see gitlab-org/gitlab#624954).
      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

      type ::Types::ArtifactRegistry::PackageDetailsType, null: true

      # Artifact Registry's own opaque identifier, not a GitLab global ID: the route carries it
      # verbatim and the client passes it straight to AR, so a GlobalIDType would reject the
      # value the caller holds.
      argument :id, GraphQL::Types::ID, # rubocop:disable Graphql/IDType -- AR-native ID, not a GitLab global ID
        required: true,
        description: 'ID of the package in Artifact Registry.'

      private

      def resolve_artifact_registry(id:)
        # A caller selects both single-artifact fields to resolve one deep link before the format
        # is known, so the mismatched one resolves null here without reaching Artifact Registry.
        return unless presented_repository.packages?

        package = artifact_registry_client.package(
          slug: artifact_registry_slug,
          repository_name: presented_repository.name,
          format: presented_repository.format,
          id: id
        )

        return unless package

        wrap_in_artifact_presenter(package)
      end
    end
  end
end
