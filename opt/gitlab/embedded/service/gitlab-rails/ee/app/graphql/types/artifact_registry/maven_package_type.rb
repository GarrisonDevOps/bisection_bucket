# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class MavenPackageType < BaseObject
      graphql_name 'ArtifactRegistryMavenPackage'
      description 'Maven package in an Artifact Registry repository.'

      # A package has no policy of its own, so this ability is never evaluated against it: the
      # organization-rooted repository field declares
      # `skip_type_authorization: [:read_artifact_registry]`, which reaches here through the
      # scoped context and empties the ability set before any policy lookup. Declared anyway, so
      # the type states what authorizes it and fails closed if that skip is ever dropped.
      authorize :read_artifact_registry

      include ::ArtifactRegistry::ExposesElementId

      exposes_element_id noun: 'package', milestone: '19.3'

      # A package owns no group or project to scope a token against.
      authorize_granular_token skip_reason: :parent_authorizes

      field :group_id, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.3' },
        description: 'Maven group ID coordinate of the package.'

      field :artifact_id, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.3' },
        description: 'Maven artifact ID coordinate of the package.'

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
