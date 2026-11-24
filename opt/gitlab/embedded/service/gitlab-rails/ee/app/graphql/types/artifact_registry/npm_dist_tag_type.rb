# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class NpmDistTagType < BaseObject
      graphql_name 'ArtifactRegistryNpmDistTag'
      description 'npm dist-tag of a package in an Artifact Registry repository.'

      # A dist-tag reaches the schema as a bare value object with no policy class, so dropping the
      # organization-rooted repository field's `skip_type_authorization` would raise in
      # `DeclarativePolicy.class_for` -- a 500, not a 403. Declared so the type states it.
      authorize :read_artifact_registry

      include ::ArtifactRegistry::ExposesElementId

      exposes_element_id noun: 'dist-tag', milestone: '19.4'

      # A dist-tag owns no group or project to scope a token against.
      authorize_granular_token skip_reason: :parent_authorizes

      field :name, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Name of the dist-tag.'

      field :version_id, GraphQL::Types::ID,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Artifact Registry ID of the version the dist-tag points at.'

      field :version, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Version string the dist-tag points at.'
    end
  end
end
