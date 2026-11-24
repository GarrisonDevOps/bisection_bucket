# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # `artifacts_count` is a contract sort column left out because the list renders no such column.
    class RepositorySortEnum < BaseEnum
      graphql_name 'ArtifactRegistryRepositorySort'
      description 'Values for sorting Artifact Registry repositories.'

      value 'NAME_ASC', value: { sort: 'name', order: 'asc' },
        description: 'Name by ascending order.'
      value 'NAME_DESC', value: { sort: 'name', order: 'desc' },
        description: 'Name by descending order.'
      value 'LAST_UPDATED_AT_ASC', value: { sort: 'last_updated_at', order: 'asc' },
        description: 'Last updated timestamp by ascending order.'
      value 'LAST_UPDATED_AT_DESC', value: { sort: 'last_updated_at', order: 'desc' },
        description: 'Last updated timestamp by descending order.'
      value 'DOWNLOADS_COUNT_ASC', value: { sort: 'downloads_count', order: 'asc' },
        description: 'Downloads count by ascending order.'
      value 'DOWNLOADS_COUNT_DESC', value: { sort: 'downloads_count', order: 'desc' },
        description: 'Downloads count by descending order.'
      value 'SIZE_BYTES_ASC', value: { sort: 'size_bytes', order: 'asc' },
        description: 'Size in bytes by ascending order.'
      value 'SIZE_BYTES_DESC', value: { sort: 'size_bytes', order: 'desc' },
        description: 'Size in bytes by descending order.'
    end
  end
end
