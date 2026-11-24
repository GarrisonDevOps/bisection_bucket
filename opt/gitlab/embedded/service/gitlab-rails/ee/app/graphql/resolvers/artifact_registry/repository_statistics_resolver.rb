# frozen_string_literal: true

module Resolvers
  module ArtifactRegistry
    class RepositoryStatisticsResolver < BaseResolver
      include ::ArtifactRegistry::ResolvesOnRepository

      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

      type ::Types::ArtifactRegistry::RepositoryStatisticsType, null: true

      private

      def resolve_artifact_registry
        return unless presented_repository.hosted?

        artifact_registry_client.repository_statistics(
          slug: artifact_registry_slug,
          repository_name: presented_repository.name,
          format: presented_repository.format
        )
      end
    end
  end
end
