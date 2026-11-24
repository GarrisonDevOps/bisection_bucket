# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class UpstreamRepositoriesResolver < BaseResolver
      include ::ArtifactRegistry::ResolvesOnRepository
      include ::ArtifactRegistry::SelectsPermissions

      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

      type [::Types::ArtifactRegistry::UpstreamRepositoryAssociationType], null: true

      private

      def resolve_artifact_registry(lookahead:)
        return unless presented_repository.virtual?

        artifact_registry_client.upstream_repositories(
          slug: artifact_registry_slug,
          repository_name: presented_repository.name,
          format: presented_repository.format,
          include_permissions: permissions_selected?(lookahead.selection(:upstream_repository))
        )
      end
    end
  end
end
