# frozen_string_literal: true

module Types
  module Cd
    class RolloutEnvironmentType < ::Types::BaseObject
      graphql_name 'CdRolloutEnvironment'
      description 'Continuous deployment rollout environment.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_rollout
      authorize_granular_token permissions: :read_cd_rollout,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::RolloutEnvironment],
        null: false,
        description: 'Global ID of the rollout environment.'

      field :position, GraphQL::Types::Int,
        null: false,
        description: 'Position of the rollout environment in the rollout sequence.'

      field :state, ::Types::Cd::RolloutEnvironmentStateEnum,
        null: false,
        description: 'State of the rollout environment.'

      field :started_at, Types::TimeType,
        null: true,
        description: 'Timestamp of when the rollout environment started.'

      field :finished_at, Types::TimeType,
        null: true,
        description: 'Timestamp of when the rollout environment finished.'

      field :rollout, ::Types::Cd::RolloutType,
        null: true,
        description: 'Rollout the rollout environment belongs to.'

      field :environment, ::Types::Cd::EnvironmentType,
        null: true,
        description: 'Environment the rollout environment targets.'

      field :deployments, ::Types::Cd::DeploymentType.connection_type,
        null: true,
        description: 'Deployments of the rollout environment.',
        resolver: ::Resolvers::Cd::DeploymentsResolver,
        experiment: { milestone: '19.2' }

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the rollout environment was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the rollout environment was last updated.'

      def rollout
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::Rollout, object.rollout_id).find
      end

      def environment
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::Environment, object.environment_id).find
      end
    end
  end
end
