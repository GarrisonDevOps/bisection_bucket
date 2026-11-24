# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # The endpoint also carries components_count and downloads_count; neither has a consumer yet,
    # so this exposes only the two figures a surface renders.
    class NamespaceStatisticsType < ::Types::BaseObject
      graphql_name 'ArtifactRegistryNamespaceStatistics'
      description 'Namespace-wide statistics for an Artifact Registry.'

      authorize :read_artifact_registry

      authorize_granular_token skip_reason: :parent_authorizes

      field :repositories_count, GraphQL::Types::BigInt,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Number of active repositories in the namespace, every format and kind.'

      # A stored counter passed through unclamped, so a reconciliation underflow can report a
      # negative until it corrects from source; a rendering surface presents that as zero.
      field :deduplicated_size_bytes, GraphQL::Types::BigInt,
        null: true,
        experiment: { milestone: '19.5' },
        description: "Namespace's storage footprint in bytes, counting each distinct blob once."
    end
  end
end
