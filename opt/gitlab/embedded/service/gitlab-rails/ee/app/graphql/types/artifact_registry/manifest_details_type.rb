# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # A subclass, so graphql-ruby emits it as a type unrelated to the list element: a list row
    # cannot select the detail-only arrays, and a detail row is its own type in the cache.
    #
    # rubocop: disable Graphql/AuthorizeTypes -- inherited from the parent's
    # `authorize :read_artifact_registry`; the cop reads only this class body
    class ManifestDetailsType < ::Types::ArtifactRegistry::ManifestType
      graphql_name 'ArtifactRegistryManifestDetails'
      description 'Single container manifest in an Artifact Registry repository, reached by ' \
        'digest under the image it belongs to (Docker and OCI).'

      # The detail endpoint serves the full arrays and no preview keys, so an inherited preview
      # would resolve null here and falsely read as a deployment predating the field.
      LIST_ONLY_FIELDS = %w[tagsPreview childrenPreview parentsPreview].freeze

      def self.fields(context = GraphQL::Query::NullContext.instance)
        super.except(*LIST_ONLY_FIELDS)
      end

      def self.get_field(field_name, context = GraphQL::Query::NullContext.instance)
        return if LIST_ONLY_FIELDS.include?(field_name)

        super
      end

      # Overrides the parent field: on this route a referrer is served like any other manifest, so
      # the value is present rather than filtered out.
      field :subject_digest, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Digest of the subject manifest this manifest refers to. Null for a manifest ' \
          'that is not a referrer. Populated here even for a referrer, unlike the manifests list, ' \
          'because the detail route serves a referrer row like any other manifest.'

      field :tags, [GraphQL::Types::String],
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Tags pointing at the manifest, name ascending. Empty when untagged. ' \
          'A window bounded by container.manifest_max_tags (1,000 by default), so it can stop ' \
          'short of tagsCount. Null on a deployment predating the field.'

      field :children, [::Types::ArtifactRegistry::ManifestPlatformType],
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Platform children of a manifest index, child digest ascending, each with ' \
          'its digest and platform triple. Empty on an image manifest and on a remote repository. ' \
          'Null on a deployment predating the field.'

      field :parent_digests, [GraphQL::Types::String],
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Digests of the indexes that reference this manifest, parent id ascending. ' \
          'Empty when no index references it. Null until Artifact Registry serves the field.'

      field :parents_count, GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Number of indexes that reference this manifest. Zero when none do. ' \
          'Null until Artifact Registry serves the field.'

      field :referrers,
        ::Types::ArtifactRegistry::ManifestType.connection_type,
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::ManifestReferrersResolver,
        connection_extension: ::Gitlab::Graphql::Extensions::ExternallyPaginatedArrayExtension,
        max_page_size: ::ArtifactRegistry::PaginatesLists::MAX_PAGE_SIZE,
        experiment: { milestone: '19.5' },
        description: 'Manifests in the image that name this manifest as their subject, ordered by ' \
          'digest ascending. ' \
          "Reads at most #{::ArtifactRegistry::PaginatesLists::MAX_PAGE_SIZE} rows per page and " \
          'can be selected once per operation, counting every selection of the field. ' \
          'Empty on a remote repository. ' \
          'Returns `null` for a manifest that is gone. Also `null` when Artifact Registry ' \
          'rejects the read: silently for a 401, 403, or 404, and alongside a top-level error ' \
          'for a 429, a 5xx, or any other 4xx.'

      field :annotations, [::Types::ArtifactRegistry::ManifestAnnotationType],
        null: true,
        experiment: { milestone: '19.5' },
        description: 'OCI annotations of the manifest, as key/value pairs. Empty when the manifest ' \
          'carried an empty annotations map, and null when it carried none: the two are kept ' \
          'apart. Always null on a remote repository, where the field is not served.'

      field :payload, GraphQL::Types::String,
        null: true,
        resolver: ::Resolvers::ArtifactRegistry::ManifestPayloadResolver,
        experiment: { milestone: '19.6' },
        description: 'Stored payload of the manifest, byte for byte, as text. On a remote repository, the ' \
          'cached payload. Makes its own Artifact Registry request and can be selected once per HTTP ' \
          'request, counting every selection in every operation of a multiplex. ' \
          'Returns `null` when the payload is not valid UTF-8, and when Artifact Registry rejects ' \
          'the read: silently for a 401, 403, or 404, and alongside a top-level error for a 429, ' \
          'a 5xx, or any other 4xx. Always `null` on a deployment predating the raw payload route.'
      # rubocop: enable Graphql/AuthorizeTypes

      # Drops any child missing a string digest so one malformed row cannot null the whole
      # non-null-element array.
      def children
        object.children&.select { |child| child['digest'].is_a?(String) }
      end

      # nil stays nil and an empty map becomes an empty list, so the two readings the field
      # documents stay apart. A pair whose value is not a string is dropped so one malformed pair
      # cannot null the whole non-null-element array.
      def annotations
        map = object.annotations
        return if map.nil?

        map.filter_map do |key, value|
          { 'key' => key, 'value' => value } if value.is_a?(String)
        end
      end
    end
  end
end
