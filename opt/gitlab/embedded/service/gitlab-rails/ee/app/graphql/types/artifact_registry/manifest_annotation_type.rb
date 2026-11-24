# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # A list of pairs rather than a JSON scalar, so a null annotations map (no key on push) stays
    # distinguishable from an empty one -- the contract keeps the two apart.
    class ManifestAnnotationType < ::Types::BaseObject
      graphql_name 'ArtifactRegistryManifestAnnotation'
      description 'OCI annotation of a container manifest in an Artifact Registry repository.'

      # A bare Hash has no policy class, so the organization-rooted field's `skip_type_authorization`
      # is what keeps `DeclarativePolicy.class_for` from raising a 500; declared so the type states
      # the ability it relies on, matching the sibling element types.
      authorize :read_artifact_registry

      authorize_granular_token skip_reason: :parent_authorizes

      field :key, GraphQL::Types::String,
        null: false,
        hash_key: 'key',
        experiment: { milestone: '19.5' },
        description: 'Annotation key.'

      field :value, GraphQL::Types::String,
        null: false,
        hash_key: 'value',
        experiment: { milestone: '19.5' },
        description: 'Annotation value.'
    end
  end
end
