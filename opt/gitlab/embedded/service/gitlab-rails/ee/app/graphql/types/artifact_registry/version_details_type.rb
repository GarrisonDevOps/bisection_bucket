# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # Holds the version fields that issue their own Artifact Registry request. graphql-ruby emits
    # a subclass as an unrelated type, so a version from the versions connection cannot select
    # them: one request per listed version fails validation rather than costing a round trip.
    #
    # rubocop: disable Graphql/AuthorizeTypes -- inherited from the parent's
    # `authorize :read_artifact_registry`; the cop reads only this class body
    class VersionDetailsType < ::Types::ArtifactRegistry::VersionType
      graphql_name 'ArtifactRegistryVersionDetails'
      description 'Single version of a package in an Artifact Registry repository, reached by ' \
        'ID and the package it is displayed under.'

      field :files,
        ::Types::ArtifactRegistry::VersionFileType.connection_type,
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::VersionFilesResolver,
        connection_extension: ::Gitlab::Graphql::Extensions::ExternallyPaginatedArrayExtension,
        max_page_size: ::ArtifactRegistry::PaginatesLists::MAX_PAGE_SIZE,
        experiment: { milestone: '19.4' },
        description: 'Files the version holds, ordered by file name. ' \
          'Reads at most 20 rows per page and can be selected once per operation. ' \
          'Returns `null` for a version that is gone, and when Artifact Registry rejects the ' \
          'read: silently for a 401, 403, or 404, and alongside a top-level error for a 429, a ' \
          '5xx, or any other 4xx.'

      field :statistics,
        ::Types::ArtifactRegistry::VersionStatisticsType,
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::VersionStatisticsResolver,
        experiment: { milestone: '19.5' },
        description: 'Read-time statistics for the version. ' \
          'Hosted repositories only, so `null` without a read on a virtual or remote ' \
          'repository and on a container repository. Can be selected once per operation. ' \
          '`null` when Artifact Registry does not serve the statistics route, and when it ' \
          'rejects the read: silently for a 401, 403, or 404, and alongside a top-level error ' \
          'for a 429, any other 5xx, or any other 4xx.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
