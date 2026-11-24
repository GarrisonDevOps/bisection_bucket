# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class ManifestType < BaseObject
      graphql_name 'ArtifactRegistryManifest'
      description 'Manifest of a container image in an Artifact Registry repository (Docker and OCI).'

      # A manifest reaches the schema as a bare value object with no policy class, so dropping
      # the repository field's `skip_type_authorization` would raise in
      # `DeclarativePolicy.class_for` -- a 500, not a 403. Declared so the type still states it.
      authorize :read_artifact_registry

      include ::ArtifactRegistry::ExposesElementId

      exposes_element_id noun: 'manifest', milestone: '19.4'

      # A manifest owns no group or project to scope a token against.
      authorize_granular_token skip_reason: :parent_authorizes

      field :digest, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Content-addressable digest of the manifest.'

      field :media_type, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Media type of the manifest.'

      field :artifact_type, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Artifact type of the manifest. Null when the manifest declares none.'

      field :subject_digest, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Digest of the subject manifest a referrer refers to. Null for a manifest ' \
          'that is not a referrer. Populated on the referrers connection, where every row is a ' \
          'referrer of the manifest it hangs off. On the manifests connection it is null unless ' \
          'the caller passes includeReferrers, which the default omits.'

      # BigInt rather than Int, matching the repository counters: a size above two gigabytes
      # overflows a GraphQL Int.
      field :size, GraphQL::Types::BigInt,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Size of the manifest, in bytes. For a hosted repository, the push-time ' \
          'tree total, where an index total already contains its platform children and so does ' \
          'not sum across sibling rows. For a remote repository, the cached manifest\'s own ' \
          'payload bytes.'

      field :created_at, ::Types::TimeType,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Time the manifest was pushed. Null if the timestamp is absent or unparseable.'

      field :architecture, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'CPU architecture an image manifest targets. Null on an index, per value on ' \
          'an image whose config did not carry it, and always null on a remote repository.'

      field :os, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Operating system an image manifest targets. Null on an index, per value on ' \
          'an image whose config did not carry it, and always null on a remote repository.'

      field :os_variant, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'CPU variant an image manifest targets. Null on an index, on most images, ' \
          'and always null on a remote repository.'

      field :tags_count, GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Number of tags pointing at the manifest. Zero when untagged. ' \
          'Null on a deployment predating the field.'

      field :referrers_count, GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Number of manifests in the image that name this digest as their subject. ' \
          'Zero when none do, and always zero on a remote repository. ' \
          'Null on a deployment predating the field.'

      field :children_count, GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Number of platform children of a manifest index. Zero on an image manifest, ' \
          'and always zero on a remote repository. Null on a deployment predating the field.'

      # rubocop: disable GraphQL/ExtractType -- tagsPreview/tagsCount and childrenPreview/childrenCount
      # stay flat siblings; nesting them under a tags/children object would diverge from AR's flat
      # ContainerManifest contract and from ArtifactRegistryManifestDetails' own flat tags/children.
      field :tags_preview, [GraphQL::Types::String],
        null: true,
        experiment: { milestone: '19.5' },
        description: 'First ten tags pointing at the manifest, name ascending. Empty when ' \
          'untagged. tagsCount on this type already carries the true total; read the complete ' \
          'tags list on the detail type. Null on a deployment predating the field.'

      field :children_preview, [::Types::ArtifactRegistry::ManifestPlatformType],
        null: true,
        experiment: { milestone: '19.5' },
        description: 'First ten platform children of a manifest index, child digest ascending, ' \
          'each with its digest and platform triple. Empty on an image manifest and on a remote ' \
          'repository. childrenCount on this type already carries the true total; read the ' \
          'complete children list on the detail type. Null on a deployment predating the field.'

      field :parents_preview, [GraphQL::Types::String],
        null: true,
        experiment: { milestone: '19.5' },
        description: 'First ten digests of the indexes that reference this manifest, in the order ' \
          'Artifact Registry returns them. Empty when no index references it. The list carries no ' \
          'parent count; read the complete list, and the total in parentsCount, on the detail ' \
          'type. Null on a deployment predating the field.'
      # rubocop: enable GraphQL/ExtractType
    end
  end
end
