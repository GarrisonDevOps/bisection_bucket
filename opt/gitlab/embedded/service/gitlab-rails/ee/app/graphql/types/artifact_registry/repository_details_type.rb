# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # Holds the repository fields that issue their own Artifact Registry request. graphql-ruby
    # emits a subclass as an unrelated type, so a repository from the list cannot select them:
    # one request per listed row fails validation rather than costing a round trip.
    #
    # rubocop: disable Graphql/AuthorizeTypes -- inherited from the parent's
    # `authorize :read_artifact_registry`; the cop reads only this class body
    class RepositoryDetailsType < ::Types::ArtifactRegistry::RepositoryType
      graphql_name 'ArtifactRegistryRepositoryDetails'
      description 'Repository in Artifact Registry, with the packages or images it holds.'

      # The single-artifact fields each issue their own Artifact Registry request, so they mount
      # here rather than on the base repository type: a repository from the list cannot select
      # them, which would cost one request per listed row. A caller selects the package and image
      # fields together to resolve one deep link before the repository format is known; the
      # mismatched one resolves null without a request.
      field :package,
        ::Types::ArtifactRegistry::PackageDetailsType,
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::PackageResolver,
        experiment: { milestone: '19.4' },
        description: 'Single package the repository holds, by Artifact Registry ID. ' \
          'Can be selected once per operation. ' \
          'Returns `null` for a repository holding images and for a package that is gone. ' \
          'Also `null` when Artifact Registry rejects the read: silently for a 401, 403, or ' \
          '404, and alongside a top-level error for a 429, a 5xx, or any other 4xx.'

      field :image,
        ::Types::ArtifactRegistry::ImageType,
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::ImageResolver,
        experiment: { milestone: '19.4' },
        description: 'Single container image the repository holds, by Artifact Registry ID. ' \
          'Can be selected once per operation. ' \
          'Returns `null` for a repository holding packages and for an image that is gone. ' \
          'Also `null` when Artifact Registry rejects the read: silently for a 401, 403, or ' \
          '404, and alongside a top-level error for a 429, a 5xx, or any other 4xx.'

      # Mounts here rather than on the package element because the Artifact Registry version route
      # addresses versions at the top level of the format segment; nesting it under the package
      # would serialize the two reads for no contract reason.
      field :version,
        ::Types::ArtifactRegistry::VersionDetailsType,
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::VersionResolver,
        experiment: { milestone: '19.4' },
        description: 'Single version the repository holds, by Artifact Registry ID and the ID ' \
          'of the package it is displayed under. ' \
          'Can be selected once per operation. ' \
          'Returns `null` for a repository holding images, for a version that is gone, and for ' \
          'a version that belongs to a different package. ' \
          'Also `null` when Artifact Registry rejects the read: silently for a 401, 403, or ' \
          '404, and alongside a top-level error for a 429, a 5xx, or any other 4xx.'

      # Mounts here rather than on the image element because the Artifact Registry manifest route
      # addresses a manifest by the image id and the digest directly under the format segment;
      # nesting it under the image would serialize the two reads for no contract reason.
      field :manifest,
        ::Types::ArtifactRegistry::ManifestDetailsType,
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::ManifestResolver,
        experiment: { milestone: '19.5' },
        description: 'Single container manifest the repository holds, by digest and the ID of ' \
          'the image it belongs to. ' \
          'Can be selected once per operation, counting every selection of the field. ' \
          '`null` while the `artifact_registry_ui` feature flag is off, resolved without a read. ' \
          'Returns `null` for a repository holding packages, for a manifest that is gone, and ' \
          'for a blank or dot-segment image ID or digest, which resolves without a read. ' \
          'Also `null` when Artifact Registry rejects the read: silently for a 401, 403, or ' \
          '404, and alongside a top-level error for a 429, a 5xx, or any other 4xx.'

      # `ArtifactRegistry::PaginatesLists` reads `max_page_size` off the field to cap the
      # outbound `limit`. Absent, it falls back to the schema default of 100.
      field :packages,
        ::Types::ArtifactRegistry::PackageType.connection_type,
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::PackagesResolver,
        connection_extension: ::Gitlab::Graphql::Extensions::ExternallyPaginatedArrayExtension,
        max_page_size: ::ArtifactRegistry::PaginatesLists::MAX_PAGE_SIZE,
        experiment: { milestone: '19.3' },
        description: 'Packages the repository holds, ordered by name. ' \
          'Can be selected once per operation, so one operation reads packages for one ' \
          'repository. ' \
          'Returns `null` for a virtual repository, for a repository holding images, ' \
          'for a repository that is gone, and when Artifact Registry rejects the read.'

      field :images,
        ::Types::ArtifactRegistry::ImageType.connection_type,
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::ImagesResolver,
        connection_extension: ::Gitlab::Graphql::Extensions::ExternallyPaginatedArrayExtension,
        max_page_size: ::ArtifactRegistry::PaginatesLists::MAX_PAGE_SIZE,
        experiment: { milestone: '19.4' },
        description: 'Images the repository holds. ' \
          'Can be selected once per operation, so one operation reads images for one ' \
          'repository. ' \
          'Returns `null` for a virtual repository, for a repository holding packages, and ' \
          'for a repository that is gone. Also `null` when Artifact Registry rejects the ' \
          'read: silently for a 401, 403, or 404, and alongside a top-level error for a ' \
          '429, a 5xx, or any other 4xx.'

      field :upstream_repositories,
        [::Types::ArtifactRegistry::UpstreamRepositoryAssociationType],
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::UpstreamRepositoriesResolver,
        experiment: { milestone: '19.5' },
        description: 'Upstream repositories a virtual repository resolves through, in resolution ' \
          'order. Can be selected once per operation. ' \
          'Returns `null` for a hosted or remote repository, for a repository that is gone, and ' \
          'when Artifact Registry rejects the read: silently for a 401, 403, or 404, and ' \
          'alongside a top-level error for a 429, a 5xx, or any other 4xx.'

      field :statistics,
        ::Types::ArtifactRegistry::RepositoryStatisticsType,
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::RepositoryStatisticsResolver,
        experiment: { milestone: '19.5' },
        description: 'Read-time package or image count of a hosted repository. ' \
          'Can be selected once per operation. ' \
          'Returns `null` without a read for a remote or virtual repository, and `null` for a ' \
          'repository that is gone. ' \
          'Also `null` when Artifact Registry rejects the read: silently for a 401, 403, or ' \
          '404, and alongside a top-level error for a 429, a 5xx, or any other 4xx.'

      field :current_user_access,
        ::Types::ArtifactRegistry::CurrentUserAccessType,
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::CurrentUserAccessResolver,
        experiment: { milestone: '19.7' },
        description: 'Access the current user has to the repository apart from their direct ' \
          'role on it. Can be selected once per operation. ' \
          'On failure the value is `null` and a top-level error carries `extensions.code`: ' \
          '`denied`, `unavailable`, `invalid_request`, or `unknown`.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
