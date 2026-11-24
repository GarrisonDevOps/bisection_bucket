# frozen_string_literal: true

module Types
  module Cd
    class ServiceType < ::Types::BaseObject
      graphql_name 'CdService'
      description 'Continuous deployment service.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_service
      authorize_granular_token permissions: :read_cd_service,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::Service],
        null: false,
        description: 'Global ID of the service.'

      field :name, GraphQL::Types::String,
        null: false,
        description: 'Name of the service.'

      field :description, GraphQL::Types::String,
        null: true,
        description: 'Description of the service.'

      field :application, ::Types::Cd::ApplicationType,
        null: false,
        description: 'Application the service belongs to.'

      field :artifact_sources, ::Types::Cd::ArtifactSourceType.connection_type,
        null: true,
        description: 'Artifact sources of the service.',
        resolver: ::Resolvers::Cd::ArtifactSourcesResolver,
        experiment: { milestone: '19.2' }

      field :service_environment_healths, ::Types::Cd::ServiceEnvironmentHealthType.connection_type,
        null: true,
        description: 'Observed health of the service across environments, ordered from worst to best. ' \
          'Request the first result to get the worst observed health of the service overall.',
        resolver: ::Resolvers::Cd::ServiceEnvironmentHealthsResolver,
        experiment: { milestone: '19.2' }

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the service was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the service was last updated.'

      field :last_deployed_at, Types::TimeType,
        null: true,
        description: "Timestamp of the service's most recently finished deployment.",
        experiment: { milestone: '19.2' }

      def application
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::Application, object.application_id).find
      end

      def last_deployed_at
        BatchLoader::GraphQL.for(object.id).batch do |service_ids, loader|
          ::Cd::Deployment.last_deployed_at_by_service(service_ids).each do |service_id, last_deployed_at|
            loader.call(service_id, last_deployed_at)
          end
        end
      end
    end
  end
end
