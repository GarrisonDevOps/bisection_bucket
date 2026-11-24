# frozen_string_literal: true

module EE
  module Types
    module Organizations
      module OrganizationType
        extend ActiveSupport::Concern

        prepended do
          field :analytics,
            ::Types::Analytics::AnalyticsType,
            null: true,
            method: :itself,
            authorize: :read_organization_analytics,
            description: 'Analytics aggregation endpoints scoped to groups and projects of the organization.',
            experiment: { milestone: '19.3' }

          field :workspaces_cluster_agents,
            ::Types::Clusters::AgentType.connection_type,
            extras: [:lookahead],
            null: true,
            description: 'Cluster agents in the organization with workspaces capabilities',
            experiment: { milestone: '17.10' },
            resolver: ::Resolvers::RemoteDevelopment::Organization::ClusterAgentsResolver

          field :work_item_settings,
            ::Types::WorkItems::SettingsType,
            null: true,
            resolver: ::Resolvers::WorkItems::SettingsResolver,
            experiment: { milestone: '19.0' },
            description: 'Work item settings for the organization.'

          field :cd_applications, ::Types::Cd::ApplicationType.connection_type,
            null: true,
            description: 'Continuous deployment applications in the organization.',
            resolver: ::Resolvers::Cd::OrganizationApplicationsResolver,
            experiment: { milestone: '19.1' }

          field :cd_application, ::Types::Cd::ApplicationType,
            null: true,
            description: 'Continuous deployment application in the organization.',
            resolver: ::Resolvers::Cd::OrganizationApplicationResolver,
            experiment: { milestone: '19.2' }

          field :cd_service, ::Types::Cd::ServiceType,
            null: true,
            description: 'Continuous deployment service in the organization.',
            resolver: ::Resolvers::Cd::OrganizationServiceResolver,
            experiment: { milestone: '19.2' }

          field :cd_environments, ::Types::Cd::EnvironmentType.connection_type,
            null: true,
            description: 'Continuous deployment environments in the organization.',
            resolver: ::Resolvers::Cd::OrganizationEnvironmentsResolver,
            experiment: { milestone: '19.1' }

          field :cd_environment, ::Types::Cd::EnvironmentType,
            null: true,
            description: 'Continuous deployment environment in the organization.',
            resolver: ::Resolvers::Cd::OrganizationEnvironmentResolver,
            experiment: { milestone: '19.2' }

          field :cd_environment_tiers, [::Types::Cd::EnvironmentTierEnum],
            null: true,
            description: 'Continuous deployment environment tiers available in the organization.',
            resolver: ::Resolvers::Cd::OrganizationEnvironmentTiersResolver,
            experiment: { milestone: '19.2' }

          field :cd_available_agents, ::Types::Clusters::AgentType.connection_type,
            null: true,
            description: 'GitLab agents for Kubernetes available in the organization.',
            resolver: ::Resolvers::Cd::OrganizationAvailableAgentsResolver,
            experiment: { milestone: '19.2' }

          field :cd_rollout, ::Types::Cd::RolloutType,
            null: true,
            description: 'Continuous deployment rollout in the organization.',
            resolver: ::Resolvers::Cd::OrganizationRolloutResolver,
            experiment: { milestone: '19.2' }

          field :cd_version_set, ::Types::Cd::VersionSetType,
            null: true,
            description: 'Continuous deployment version set in the organization.',
            resolver: ::Resolvers::Cd::OrganizationVersionSetResolver,
            experiment: { milestone: '19.2' }

          field :policy_store, ::Types::Govern::PolicyStoreType,
            null: true,
            resolver: ::Resolvers::Govern::PolicyStoreResolver,
            complexity: 10,
            experiment: { milestone: '19.4' },
            description: 'Policy store catalogs. ' \
              'Returns `null` when the policy store experiment is not active for the organization.'

          field :security_metrics,
            ::Types::Security::SecurityMetricsType,
            null: true,
            description: 'Security metrics aggregated across the organization. ' \
              'Available only when the `organization_security_dashboard` feature flag is enabled. ' \
              'This feature is currently under development and not yet available for general use.',
            resolver: ::Resolvers::Security::SecurityMetricsResolver,
            experiment: { milestone: '19.3' }

          # The field authorizes read_artifact_registry against the organization; the
          # resolved value is a struct with no policy of its own, so the type's read
          # gate is skipped rather than re-checked.
          field :artifact_registry,
            ::Types::ArtifactRegistry::RegistryType,
            null: true,
            authorize: :read_artifact_registry,
            skip_type_authorization: [:read_artifact_registry],
            description: 'Artifact Registry the organization is activated for. ' \
              'Returns `null` when the organization has no registry, or when the ' \
              '`artifact_registry_ui` feature flag is disabled.',
            resolver: ::Resolvers::ArtifactRegistry::RegistryResolver,
            experiment: { milestone: '19.4' }

          # The nodes are Artifact Registry value objects with no policy of their own, so the
          # per-node repeat of the type-level ability is skipped: the field already ran it
          # against the organization the connection hangs off.
          field :artifact_registry_repositories,
            ::Types::ArtifactRegistry::RepositoryType.connection_type,
            null: true,
            authorize: :read_artifact_registry,
            skip_type_authorization: [:read_artifact_registry],
            description: 'Artifact Registry repositories in the organization. ' \
              'Returns `null` when the `artifact_registry_ui` feature flag is disabled. ' \
              'Raises a resource-not-available error when the organization is not activated ' \
              'for Artifact Registry, where `artifactRegistry` returns `null` instead.',
            resolver: ::Resolvers::ArtifactRegistry::RepositoriesResolver,
            connection_extension: ::Gitlab::Graphql::Extensions::ExternallyPaginatedArrayExtension,
            experiment: { milestone: '19.3' }

          field :artifact_registry_repository,
            ::Types::ArtifactRegistry::RepositoryDetailsType,
            null: true,
            authorize: :read_artifact_registry,
            skip_type_authorization: [:read_artifact_registry],
            description: 'Single Artifact Registry repository in the organization, by name. ' \
              'Returns `null` when not found or when the `artifact_registry_ui` feature flag is disabled. ' \
              'Raises a resource-not-available error when the organization is not activated ' \
              'for Artifact Registry, where `artifactRegistry` returns `null` instead.',
            resolver: ::Resolvers::ArtifactRegistry::RepositoryResolver,
            experiment: { milestone: '19.3' }

          field :cd_available_deploy_drivers, [GraphQL::Types::String],
            null: true,
            description: 'Reference of continuous deployment deploy drivers available in the organization.',
            resolver: ::Resolvers::Cd::OrganizationAvailableDeployDriversResolver,
            experiment: { milestone: '19.2' }

          field :security_tracked_context_quota, ::Types::Security::TrackedContextQuotaType,
            null: true,
            description: 'Quota information for tracked security contexts in the organization.',
            experiment: { milestone: '19.6' }

          def security_tracked_context_quota
            return unless Ability.allowed?(current_user, :update_organization, object)

            ::Security::TrackedContextQuotaService.new(object).quota_info
          end
        end
      end
    end
  end
end
