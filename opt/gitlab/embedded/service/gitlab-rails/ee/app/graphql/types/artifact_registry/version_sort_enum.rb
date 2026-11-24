# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # The version sort orders lexicographically by database collation, not by semantic version
    # precedence, so the value descriptions say alphabetical rather than "newest version".
    class VersionSortEnum < BaseEnum
      graphql_name 'ArtifactRegistryVersionSort'
      description 'Values for sorting Artifact Registry package versions.'

      # On a remote repository `created_at` is the cache-fill time, so this orders by cache
      # recency (the order versions were first pulled) rather than the upstream publish order.
      value 'CREATED_AT_ASC', value: { sort: 'created_at', order: 'asc' },
        description: 'Publication date by ascending order.'
      value 'CREATED_AT_DESC', value: { sort: 'created_at', order: 'desc' },
        description: 'Publication date by descending order.'
      value 'VERSION_ASC', value: { sort: 'version', order: 'asc' },
        description: 'Version string by ascending, alphabetical order.'
      value 'VERSION_DESC', value: { sort: 'version', order: 'desc' },
        description: 'Version string by descending, alphabetical order.'
    end
  end
end
