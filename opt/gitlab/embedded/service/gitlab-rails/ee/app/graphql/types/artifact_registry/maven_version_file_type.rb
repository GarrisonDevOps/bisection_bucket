# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class MavenVersionFileType < BaseObject
      graphql_name 'ArtifactRegistryMavenVersionFile'
      description 'File of a Maven version in an Artifact Registry repository.'

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

      field :sha1, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'SHA-1 checksum of the file.'

      field :sha512, GraphQL::Types::String,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'SHA-512 checksum of the file.'

      field :md5, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'MD5 checksum of the file. Null when the deploy stored none.'

      field :created_at, ::Types::TimeType,
        null: true,
        experiment: { milestone: '19.4' },
        description: 'Timestamp the file was stored. Null until Artifact Registry serializes the ' \
          'Maven file timestamp.'
    end
  end
end
