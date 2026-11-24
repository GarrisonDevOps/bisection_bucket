# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # One child of a manifest index: its digest plus its platform triple, carried in the same read
    # so a caller needs no detail call per child. The triple is nullable per value, not as a unit.
    class ManifestPlatformType < ::Types::BaseObject
      graphql_name 'ArtifactRegistryManifestPlatform'
      description 'Platform child of a container manifest index in an Artifact Registry repository.'

      # A bare Hash has no policy class, so the organization-rooted field's `skip_type_authorization`
      # is what keeps `DeclarativePolicy.class_for` from raising a 500; declared so the type states
      # the ability it relies on, matching the sibling element types.
      authorize :read_artifact_registry

      authorize_granular_token skip_reason: :parent_authorizes

      field :digest, GraphQL::Types::String,
        null: false,
        hash_key: 'digest',
        experiment: { milestone: '19.5' },
        description: 'Content-addressable digest of the child manifest.'

      field :architecture, GraphQL::Types::String,
        null: true,
        hash_key: 'architecture',
        experiment: { milestone: '19.5' },
        description: 'CPU architecture the child targets. Null when the manifest carries none.'

      field :os, GraphQL::Types::String,
        null: true,
        hash_key: 'os',
        experiment: { milestone: '19.5' },
        description: 'Operating system the child targets. Null when the manifest carries none.'

      field :os_variant, GraphQL::Types::String,
        null: true,
        hash_key: 'os_variant',
        experiment: { milestone: '19.5' },
        description: 'CPU variant the child targets. Null when the manifest carries none, ' \
          'which is most images.'
    end
  end
end
