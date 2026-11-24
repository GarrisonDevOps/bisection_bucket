# frozen_string_literal: true

module Types
  module Cd
    class VersionType < ::Types::BaseObject
      graphql_name 'CdVersion'
      description 'Continuous deployment artifact version.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_artifact_source
      authorize_granular_token permissions: :read_cd_artifact_source,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::Version],
        null: false,
        description: 'Global ID of the version.'

      field :name, GraphQL::Types::String,
        null: false,
        description: 'Name of the version.'

      field :digest, GraphQL::Types::String,
        null: true,
        description: 'Digest of the version.'

      field :reference, GraphQL::Types::String,
        null: true,
        description: 'Reference of the version.'

      field :verified, GraphQL::Types::Boolean,
        null: false,
        description: 'Indicates the version was observed being pushed to the artifact source, ' \
          'rather than entered as a free-text name.'

      field :artifact_source, ::Types::Cd::ArtifactSourceType,
        null: true,
        description: 'Artifact source the version belongs to.'

      field :environments, ::Types::Cd::EnvironmentType.connection_type,
        null: true,
        description: 'Distinct environments the version has been deployed to.',
        resolver: ::Resolvers::Cd::VersionEnvironmentsResolver,
        experiment: { milestone: '19.2' }

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the version was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the version was last updated.'

      def artifact_source
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::ArtifactSource, object.artifact_source_id).find
      end
    end
  end
end
