# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class ImageType < BaseObject
      graphql_name 'ArtifactRegistryImage'
      description 'Image in an Artifact Registry repository.'

      # See MavenPackageType: the ability is never evaluated against an image, because the
      # organization-rooted repository field's `skip_type_authorization` empties the ability set
      # before any policy lookup. Declared so the type states what authorizes it.
      authorize :read_artifact_registry

      include ::ArtifactRegistry::ExposesElementId

      exposes_element_id noun: 'image', milestone: '19.4'

      # An image is only reachable through the repository field, which authorizes against the
      # organization, and it owns no group or project to scope a token against.
      authorize_granular_token skip_reason: :parent_authorizes

      field :name, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Name of the image.'

      field :last_downloaded_at, ::Types::TimeType,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Timestamp the image was last pulled. Null when it was never pulled.'

      field :manifests,
        ::Types::ArtifactRegistry::ManifestType.connection_type,
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::ManifestsResolver,
        connection_extension: ::Gitlab::Graphql::Extensions::ExternallyPaginatedArrayExtension,
        max_page_size: ::ArtifactRegistry::PaginatesLists::MAX_PAGE_SIZE,
        experiment: { milestone: '19.4' },
        description: 'Manifests of the image, ordered by publication date descending by default. ' \
          "Reads at most #{::ArtifactRegistry::PaginatesLists::MAX_PAGE_SIZE} rows per page " \
          "and can be selected for up to #{::ArtifactRegistry::PaginatesLists::MAX_PAGE_SIZE} " \
          'images per operation, matching the images page size. ' \
          'Returns `null` for an image that is gone. Also `null` when Artifact Registry ' \
          'rejects the read: silently for a 401, 403, or 404, and alongside a top-level error ' \
          'for a 429, a 5xx, or any other 4xx.'
    end
  end
end
