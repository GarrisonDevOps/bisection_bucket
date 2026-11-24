# frozen_string_literal: true

module Types
  module Cd
    class VersionSetEntryType < ::Types::BaseObject
      graphql_name 'CdVersionSetEntry'
      description 'Continuous deployment version set entry.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_version_set
      authorize_granular_token permissions: :read_cd_version_set,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::VersionSetEntry],
        null: false,
        description: 'Global ID of the version set entry.'

      field :version_set, ::Types::Cd::VersionSetType,
        null: true,
        description: 'Version set the entry belongs to.'

      field :version, ::Types::Cd::VersionType,
        null: true,
        description: 'Version the entry references.'

      field :artifact_source, ::Types::Cd::ArtifactSourceType,
        null: true,
        description: 'Artifact source the entry references.'

      field :service, ::Types::Cd::ServiceType,
        null: true,
        description: 'Service the entry references.'

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the version set entry was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the version set entry was last updated.'

      def version_set
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::VersionSet, object.version_set_id).find
      end

      def version
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::Version, object.version_id).find
      end

      def artifact_source
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::ArtifactSource, object.artifact_source_id).find
      end

      def service
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::Service, object.service_id).find
      end
    end
  end
end
