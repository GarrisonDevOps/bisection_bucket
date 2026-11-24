# frozen_string_literal: true

module Types
  module Cd
    class ApplicationType < ::Types::BaseObject
      graphql_name 'CdApplication'
      description 'Continuous deployment application.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_application
      authorize_granular_token permissions: :read_cd_application,
        boundary: :instance,
        boundary_type: :instance

      field :id, Types::GlobalIDType[::Cd::Application],
        null: false,
        description: 'Global ID of the application.'

      field :name, GraphQL::Types::String,
        null: false,
        description: 'Name of the application.'

      field :description, GraphQL::Types::String,
        null: true,
        description: 'Description of the application.'

      field :organization, ::Types::Organizations::OrganizationType,
        null: true,
        description: 'Organization the application belongs to.'

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the application was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the application was last updated.'

      field :services, ::Types::Cd::ServiceType.connection_type,
        null: true,
        description: 'Services belonging to the application.',
        resolver: ::Resolvers::Cd::ServicesResolver,
        experiment: { milestone: '19.2' }

      field :version_sets, ::Types::Cd::VersionSetType.connection_type,
        null: true,
        description: 'Version sets of the application.',
        resolver: ::Resolvers::Cd::VersionSetsResolver,
        experiment: { milestone: '19.2' }

      field :rollouts, ::Types::Cd::RolloutType.connection_type,
        null: true,
        description: 'Rollouts of the application.',
        resolver: ::Resolvers::Cd::RolloutsResolver,
        experiment: { milestone: '19.2' }

      field :application_flow_definitions, ::Types::Cd::ApplicationFlowDefinitionType.connection_type,
        null: true,
        description: 'Flow definitions of the application.',
        resolver: ::Resolvers::Cd::ApplicationFlowDefinitionsResolver,
        experiment: { milestone: '19.2' }

      field :links, ::Types::Cd::ApplicationLinkType.connection_type,
        null: true,
        description: 'Links belonging to the application.',
        resolver: ::Resolvers::Cd::ApplicationLinksResolver,
        experiment: { milestone: '19.2' }

      field :environments, ::Types::Cd::EnvironmentType.connection_type,
        null: true,
        description: "Distinct environments the application has been rolled out to, " \
          "based on the application's most recent rollouts.",
        resolver: ::Resolvers::Cd::ApplicationEnvironmentsResolver,
        experiment: { milestone: '19.2' }

      field :deployments, ::Types::Cd::DeploymentType.connection_type,
        null: true,
        description: 'Deployments actuated by the application, across its most recent rollouts and environments.',
        resolver: ::Resolvers::Cd::ApplicationDeploymentsResolver,
        experiment: { milestone: '19.2' }

      field :last_deployed_at, Types::TimeType,
        null: true,
        description: "Timestamp of the application's most recently finished deployment, " \
          "among its most recent rollouts.",
        experiment: { milestone: '19.2' }

      field :user_permissions, Types::PermissionTypes::Cd::Application,
        null: true,
        description: 'Permissions of the current user for the application.',
        method: :itself,
        experiment: { milestone: '19.2' }

      field :health, ::Types::Cd::ServiceHealthEnum,
        null: true,
        description: "Worst health reported across the application's services, " \
          'or null when no health has been reported.',
        experiment: { milestone: '19.2' }

      field :status, ::Types::Cd::ApplicationStatusEnum,
        null: true,
        description: "Current status of the application, derived from its services' worst health and " \
          'whether it has a rollout in progress, or null when neither applies.',
        experiment: { milestone: '19.3' }

      def organization
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Organizations::Organization, object.organization_id).find
      end

      def health
        BatchLoader::GraphQL.for(object.id).batch do |application_ids, loader|
          ::Cd::ServiceEnvironmentHealth.for_application(application_ids).worst_per_application.each do |health|
            loader.call(health.application_id, health.health)
          end
        end
      end

      def status
        BatchLoader::GraphQL.for(object.id).batch do |application_ids, loader|
          ::Cd::Application.statuses_by_id(application_ids).each do |application_id, status|
            loader.call(application_id, status)
          end
        end
      end
    end
  end
end
