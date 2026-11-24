# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class VersionResolver < BaseResolver
      include ::ArtifactRegistry::ResolvesOnRepository

      # A second `version` selection in one operation raises rather than issuing another request.
      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

      type ::Types::ArtifactRegistry::VersionDetailsType, null: true

      # AR-native IDs, not GitLab global IDs: a GlobalIDType would reject the value the caller holds.
      argument :id, GraphQL::Types::ID, # rubocop:disable Graphql/IDType -- AR-native ID, not a GitLab global ID
        required: true,
        description: 'ID of the version in Artifact Registry.'

      argument :artifact_id, GraphQL::Types::ID, # rubocop:disable Graphql/IDType -- AR-native ID, not a GitLab global ID
        required: true,
        description: 'ID of the package the version is displayed under, in Artifact Registry. ' \
          'The version resolves `null` when it belongs to a different package.'

      private

      def resolve_artifact_registry(id:, artifact_id:)
        # Client#version raises on a container repository; holding the format resolves null with
        # no request instead, honoring the silent null the field promises.
        return unless presented_repository.packages?

        version = artifact_registry_client.version(
          slug: artifact_registry_slug,
          repository_name: presented_repository.name,
          format: presented_repository.format,
          version_id: id
        )

        return unless version

        # Fails open on an absent `package_id`: rejecting it would null every version on a
        # deployment predating the serialization patch, and both resources sit under one
        # repository the viewer can already read.
        return if version.package_id.present? && version.package_id != artifact_id

        ::ArtifactRegistry::VersionPresenter.new(version, repository: presented_repository)
      end
    end
  end
end
