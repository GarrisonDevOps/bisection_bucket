# frozen_string_literal: true

module Types
  module Cd
    class ServiceEnvironmentHealthType < ::Types::BaseObject
      graphql_name 'CdServiceEnvironmentHealth'
      description 'Observed health of a continuous deployment service in an environment.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_service
      authorize_granular_token permissions: :read_cd_service,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::ServiceEnvironmentHealth],
        null: false,
        description: 'Global ID of the service environment health.'

      field :health, ::Types::Cd::ServiceHealthEnum,
        null: false,
        description: 'Observed health of the service in the environment.'

      field :observed_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the health was observed.'

      field :service, ::Types::Cd::ServiceType,
        null: true,
        description: 'Service the health belongs to.'

      field :environment, ::Types::Cd::EnvironmentType,
        null: true,
        description: 'Environment the health belongs to.'

      field :deployed_versions, ::Types::Cd::VersionType.connection_type,
        null: true,
        description: 'Versions of the service currently deployed in this environment.',
        resolver: ::Resolvers::Cd::ServiceEnvironmentDeployedVersionsResolver,
        experiment: { milestone: '19.3' }

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the service environment health was created.'

      def service
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::Service, object.service_id).find
      end

      def environment
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::Environment, object.environment_id).find
      end
    end
  end
end
