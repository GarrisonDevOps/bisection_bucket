# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # Publication date alone, which is all the manifests endpoint offers.
    class ManifestSortEnum < BaseEnum
      graphql_name 'ArtifactRegistryManifestSort'
      description 'Values for sorting Artifact Registry container manifests.'

      # On a remote repository `created_at` is the cache-fill time, so this orders by cache
      # recency (the order manifests were first pulled) rather than the upstream publish order.
      value 'CREATED_AT_ASC', value: { sort: 'created_at', order: 'asc' },
        description: 'Publication date by ascending order.'
      value 'CREATED_AT_DESC', value: { sort: 'created_at', order: 'desc' },
        description: 'Publication date by descending order.'
    end
  end
end
