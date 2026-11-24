# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class RepositoryStatisticsType < ::Types::BaseObject
      graphql_name 'ArtifactRegistryRepositoryStatistics'
      description 'Read-time statistics for a hosted repository in Artifact Registry.'

      authorize :read_artifact_registry

      authorize_granular_token skip_reason: :parent_authorizes

      field :packages_count, GraphQL::Types::BigInt,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Number of packages the repository holds, computed at read time. ' \
          '`null` for a repository holding images.'

      field :images_count, GraphQL::Types::BigInt,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Number of images the repository holds, computed at read time. ' \
          '`null` for a repository holding packages.'
    end
  end
end
