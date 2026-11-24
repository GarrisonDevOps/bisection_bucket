# frozen_string_literal: true

module Types
  module Cd
    class DeploymentType < ::Types::BaseObject
      graphql_name 'CdDeployment'
      description 'Continuous deployment deployment.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_rollout
      authorize_granular_token permissions: :read_cd_rollout,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::Deployment],
        null: false,
        description: 'Global ID of the deployment.'

      field :state, ::Types::Cd::DeploymentStateEnum,
        null: false,
        description: 'State of the deployment.'

      field :started_at, Types::TimeType,
        null: true,
        description: 'Timestamp of when the deployment started.'

      field :finished_at, Types::TimeType,
        null: true,
        description: 'Timestamp of when the deployment finished.'

      field :service, ::Types::Cd::ServiceType,
        null: true,
        description: 'Service being deployed.'

      field :rollout_environment, ::Types::Cd::RolloutEnvironmentType,
        null: true,
        description: 'Rollout environment the deployment belongs to.'

      field :deployment_transitions, ::Types::Cd::DeploymentTransitionType.connection_type,
        null: true,
        description: 'Transition journal of the deployment.',
        resolver: ::Resolvers::Cd::DeploymentTransitionsResolver,
        experiment: { milestone: '19.2' }

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the deployment was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the deployment was last updated.'

      def service
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::Service, object.service_id).find
      end

      def rollout_environment
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::RolloutEnvironment, object.rollout_environment_id).find
      end
    end
  end
end
