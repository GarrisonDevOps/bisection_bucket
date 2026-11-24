# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class NpmPackageType < BaseObject
      graphql_name 'ArtifactRegistryNpmPackage'
      description 'npm package in an Artifact Registry repository.'

      # See MavenPackageType: the ability is never evaluated against a package, because the
      # organization-rooted repository field's `skip_type_authorization` empties the ability set
      # before any policy lookup. Declared so the type states what authorizes it.
      authorize :read_artifact_registry

      include ::ArtifactRegistry::ExposesElementId

      exposes_element_id noun: 'package', milestone: '19.3'

      # A package owns no group or project to scope a token against.
      authorize_granular_token skip_reason: :parent_authorizes

      field :name, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.3' },
        description: 'Name of the package, including its scope when it has one.'

      field :scope, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.3' },
        description: 'npm scope of the package. Null for an unscoped package.'

      field :versions_count, GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '19.3' },
        description: 'Number of versions of the package. Buffered, so it can lag the version list. ' \
          'Null for a package of a remote repository, which Artifact Registry supplies no count for.'

      field :last_downloaded_at, ::Types::TimeType,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Timestamp the package was last pulled. Null when it was never pulled.'

      field :versions,
        ::Types::ArtifactRegistry::VersionType.connection_type,
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::VersionsResolver,
        connection_extension: ::Gitlab::Graphql::Extensions::ExternallyPaginatedArrayExtension,
        max_page_size: 20,
        experiment: { milestone: '19.4' },
        description: 'Versions of the package, ordered by publication date descending by default. ' \
          'Resolves at most once per package in a page, so one operation reads versions for ' \
          'up to 20 packages. ' \
          'Returns `null` for a package that is gone. Also `null` when Artifact Registry ' \
          'rejects the read: silently for a 401, 403, or 404, and alongside a top-level error ' \
          'for a 429, a 5xx, or any other 4xx.'
    end
  end
end
