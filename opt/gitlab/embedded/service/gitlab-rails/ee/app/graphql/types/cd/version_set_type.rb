# frozen_string_literal: true

module Types
  module Cd
    class VersionSetType < ::Types::BaseObject
      graphql_name 'CdVersionSet'
      description 'Continuous deployment version set.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_version_set
      authorize_granular_token permissions: :read_cd_version_set,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::VersionSet],
        null: false,
        description: 'Global ID of the version set.'

      field :name, GraphQL::Types::String,
        null: false,
        description: 'Name of the version set.'

      field :description, GraphQL::Types::String,
        null: true,
        description: 'Description of the version set.'

      field :entries_digest, GraphQL::Types::String,
        null: true,
        description: 'Digest of the version set entries.'

      field :application, ::Types::Cd::ApplicationType,
        null: true,
        description: 'Application the version set belongs to.'

      field :version_set_entries, ::Types::Cd::VersionSetEntryType.connection_type,
        null: true,
        description: 'Entries of the version set.',
        resolver: ::Resolvers::Cd::VersionSetEntriesResolver,
        experiment: { milestone: '19.2' }

      field :rollouts, ::Types::Cd::RolloutType.connection_type,
        null: true,
        description: 'Rollouts of the version set.',
        resolver: ::Resolvers::Cd::RolloutsResolver,
        experiment: { milestone: '19.2' }

      field :author, Types::UserType,
        null: true,
        description: 'User who created the version set. Null if it was created before author tracking was added.',
        experiment: { milestone: '19.3' }

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the version set was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the version set was last updated.'

      field :status, ::Types::Cd::VersionSetStatusEnum,
        null: true,
        description: 'High-level lifecycle status of the release, or null when the release is currently ' \
          'live and has not been superseded or rolled back.',
        experiment: { milestone: '19.3' }

      def application
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::Application, object.application_id).find
      end

      def status
        BatchLoader::GraphQL.for(object.id).batch do |version_set_ids, loader|
          ::Cd::VersionSet.statuses_by_id(version_set_ids).each do |version_set_id, status|
            loader.call(version_set_id, status)
          end
        end
      end

      def author
        return unless object.created_by_id

        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::User, object.created_by_id).find
      end
    end
  end
end
