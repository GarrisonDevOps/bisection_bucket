# frozen_string_literal: true

module Types
  module Cd
    class EnvironmentType < ::Types::BaseObject
      graphql_name 'CdEnvironment'
      description 'Continuous deployment environment.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_environment
      authorize_granular_token permissions: :read_cd_environment,
        boundary: :instance,
        boundary_type: :instance

      field :id, Types::GlobalIDType[::Cd::Environment],
        null: false,
        description: 'Global ID of the environment.'

      field :name, GraphQL::Types::String,
        null: false,
        description: 'Name of the environment.'

      field :description, GraphQL::Types::String,
        null: true,
        description: 'Description of the environment.'

      field :tier, ::Types::Cd::EnvironmentTierEnum,
        null: false,
        description: 'Tier of the environment.'

      field :organization, ::Types::Organizations::OrganizationType,
        null: true,
        description: 'Organization the environment belongs to.'

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the environment was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the environment was last updated.'

      field :environment_driver_bindings, ::Types::Cd::EnvironmentDriverBindingType.connection_type,
        null: true,
        description: 'Driver bindings of the environment.',
        resolver: ::Resolvers::Cd::EnvironmentDriverBindingsResolver,
        experiment: { milestone: '19.2' }

      field :service_environment_healths, ::Types::Cd::ServiceEnvironmentHealthType.connection_type,
        null: true,
        description: 'Observed service health in the environment.',
        resolver: ::Resolvers::Cd::ServiceEnvironmentHealthsResolver,
        experiment: { milestone: '19.2' }

      field :rollout_environments, ::Types::Cd::RolloutEnvironmentType.connection_type,
        null: true,
        description: 'Rollout environments of the environment.',
        resolver: ::Resolvers::Cd::RolloutEnvironmentsResolver,
        experiment: { milestone: '19.2' }

      field :latest_finished_rollout_environment, ::Types::Cd::RolloutEnvironmentType,
        null: true,
        description: 'Most recently finished rollout environment for the environment.',
        experiment: { milestone: '19.4' }

      field :applications_count, GraphQL::Types::Int,
        null: false,
        description: 'Number of applications with services in the environment.',
        experiment: { milestone: '19.3' }

      field :applications, ::Types::Cd::EnvironmentApplicationType.connection_type,
        null: true,
        description: 'Applications with services in the environment, each with its service count in the environment.',
        resolver: ::Resolvers::Cd::EnvironmentApplicationsResolver,
        experiment: { milestone: '19.3' }

      field :services_count, GraphQL::Types::Int,
        null: false,
        description: 'Number of services with observed health in the environment.',
        experiment: { milestone: '19.3' }

      field :health_status, ::Types::Cd::ServiceHealthEnum,
        null: true,
        description: 'Worst observed service health across the environment. ' \
          'Null when no service health has been reported.',
        experiment: { milestone: '19.4' }

      def organization
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Organizations::Organization, object.organization_id).find
      end

      def latest_finished_rollout_environment
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        BatchLoader::GraphQL.for(object.id).batch(
          default_value: nil,
          key: :latest_finished_rollout_environment
        ) do |environment_ids, loader|
          records = ::Cd::RolloutEnvironment.latest_finished_per_environment(environment_ids)

          records.each { |record| loader.call(record.environment_id, record) }
        end
      end

      def applications_count
        BatchLoader::GraphQL.for(object.id).batch(default_value: 0) do |environment_ids, loader|
          counts = ::Cd::ServiceEnvironmentHealth.applications_count_by_environment(environment_ids)

          counts.each { |environment_id, count| loader.call(environment_id, count) }
        end
      end

      def services_count
        BatchLoader::GraphQL.for(object.id).batch(default_value: 0) do |environment_ids, loader|
          counts = ::Cd::ServiceEnvironmentHealth.services_count_by_environment(environment_ids)

          counts.each { |environment_id, count| loader.call(environment_id, count) }
        end
      end

      # No default_value: environments absent from the rollup resolve to nil,
      # distinguishing "no signal yet" from an observed unknown health.
      def health_status
        BatchLoader::GraphQL.for(object.id).batch do |environment_ids, loader|
          ::Cd::ServiceEnvironmentHealth.for_environment(environment_ids).worst_per_environment.each do |health|
            loader.call(health.environment_id, health.health)
          end
        end
      end
    end
  end
end
