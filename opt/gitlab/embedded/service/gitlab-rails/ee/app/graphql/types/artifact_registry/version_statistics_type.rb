# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # Point-in-time figures for one version. Phase 1 exposes filesCount alone; the endpoint's
    # size_bytes and last_downloaded_at are not rendered, so this omits them (the monolith/S04
    # rule: read only what the slice renders).
    class VersionStatisticsType < ::Types::BaseObject
      graphql_name 'ArtifactRegistryVersionStatistics'
      description 'Read-time statistics for a version in an Artifact Registry repository.'

      authorize :read_artifact_registry

      authorize_granular_token skip_reason: :parent_authorizes

      field :files_count, GraphQL::Types::BigInt,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Number of files the version holds, computed at read time.'
    end
  end
end
