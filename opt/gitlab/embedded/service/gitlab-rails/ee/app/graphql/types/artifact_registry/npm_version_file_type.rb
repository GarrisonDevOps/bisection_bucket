# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class NpmVersionFileType < BaseObject
      graphql_name 'ArtifactRegistryNpmVersionFile'
      description 'File of an npm version in an Artifact Registry repository.'

      authorize :read_artifact_registry

      include ::ArtifactRegistry::ExposesElementId

      exposes_element_id noun: 'file', milestone: '19.4'

      authorize_granular_token skip_reason: :parent_authorizes

      field :file_name, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Name of the file.'

      field :size_bytes, GraphQL::Types::BigInt,
        null: false,
        method: :size,
        experiment: { milestone: '19.4' },
        description: 'Stored size of the file in bytes.'

      field :sha256, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'SHA-256 checksum of the file.'

      field :created_at, ::Types::TimeType,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Timestamp the file was stored. Null on a remote repository, whose cached ' \
          'row carries none.'
    end
  end
end
