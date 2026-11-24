# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # The npm arm of ArtifactRegistryPackageDetails (see PackageDetailsType); mounts distTags.
    #
    # rubocop: disable Graphql/AuthorizeTypes -- inherited from the parent's
    # `authorize :read_artifact_registry`; the cop reads only this class body
    class NpmPackageDetailsType < ::Types::ArtifactRegistry::NpmPackageType
      graphql_name 'ArtifactRegistryNpmPackageDetails'
      description 'A single npm package in an Artifact Registry repository, returned by the by-ID ' \
        'package read; carries the npm dist-tags.'

      DIST_TAGS_MAX_PAGE_SIZE = 100

      field :dist_tags,
        ::Types::ArtifactRegistry::NpmDistTagType.connection_type,
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::NpmDistTagsResolver,
        connection_extension: ::Gitlab::Graphql::Extensions::ExternallyPaginatedArrayExtension,
        max_page_size: DIST_TAGS_MAX_PAGE_SIZE,
        experiment: { milestone: '19.4' },
        description: 'npm dist-tags of the package, ordered by name. ' \
          'Truncates above 100 dist-tags. ' \
          'Can be selected once per operation. `null` without a read on a remote repository, ' \
          'which Artifact Registry serves no dist-tag rows for. Also `null` for a package that ' \
          'is gone, and when Artifact Registry rejects the read: silently for a 401, 403, or ' \
          '404, and alongside a top-level error for a 429, a 5xx, or any other 4xx.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
