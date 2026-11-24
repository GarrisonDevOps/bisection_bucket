# frozen_string_literal: true

module EE
  module Types
    module QueryType
      extend ActiveSupport::Concern
      prepended do
        field :add_on_purchases,
          [::Types::GitlabSubscriptions::AddOnPurchaseType],
          null: true,
          description: 'Retrieve all active add-on purchases. ' \
                       'This query can be used in GitLab.com and self-managed environments.',
          resolver: ::Resolvers::GitlabSubscriptions::AddOnPurchasesResolver
        field :functional_verification_status,
          ::Types::Ai::FunctionalVerificationCheck::StatusType,
          null: true,
          resolver: ::Resolvers::Ai::FunctionalVerificationCheck::StatusResolver,
          experiment: { milestone: '19.5' },
          description: 'Status of a GitLab Duo Agent Platform functional verification check.'
        field :artifact_registry_role_assignments,
          resolver: ::Resolvers::ArtifactRegistry::RoleAssignmentsResolver,
          connection_extension: ::Gitlab::Graphql::Extensions::ForwardOnlyExternallyPaginatedArrayExtension,
          max_page_size: ::Resolvers::ArtifactRegistry::RoleAssignmentsResolver::MAX_PAGE_SIZE,
          experiment: { milestone: '19.3' },
          description: 'Direct Artifact Registry role assignments on the given resources. ' \
                       'Returns only roles assigned on a resource itself, not members who ' \
                       'inherit access from a membership on an ancestor namespace, so it is ' \
                       'not a complete list of everyone who can access the resource.'
        field :ai_catalog_agent_flow_config,
          resolver: ::Resolvers::Ai::Catalog::AgentFlowConfigResolver,
          null: true,
          description: 'Get flow configuration for an AI Catalog agent.',
          experiment: { milestone: '18.4' }
        field :ai_catalog_built_in_tools, ::Types::Ai::Catalog::BuiltInToolType.connection_type,
          max_page_size: 1_000,
          null: true,
          description: 'List of AI Catalog built-in tools.',
          experiment: { milestone: '18.3' },
          directives: granular_scope_directive(
            permissions: :read_ai_catalog_item, boundary: :user, boundary_type: :user
          )
        field :ai_catalog_mcp_tools, ::Types::Ai::Catalog::McpToolType.connection_type,
          max_page_size: 1_000,
          null: false,
          description: 'List of MCP tools dynamically discovered from the GitLab MCP server.',
          experiment: { milestone: '18.11' }
        field :ai_catalog_item,
          resolver: ::Resolvers::Ai::Catalog::ItemResolver,
          null: true,
          experiment: { milestone: '18.2' }
        field :ai_catalog_items,
          resolver: ::Resolvers::Ai::Catalog::ItemsResolver,
          null: false,
          experiment: { milestone: '18.2' },
          description: 'List of AI Catalog items.'
        field :ai_catalog_custom_and_foundational_items,
          resolver: ::Resolvers::Ai::Catalog::CustomAndFoundationalItemsResolver,
          null: false,
          experiment: { milestone: '19.0' },
          description: 'List of AI Catalog items, including foundational items.'
        field :ai_catalog_item_versions,
          resolver: ::Resolvers::Ai::Catalog::ItemVersionsResolver,
          null: false,
          experiment: { milestone: '18.8' },
          description: 'Public AI Catalog item versions.'
        field :ai_flows_metadata,
          resolver: ::Resolvers::Ai::FlowsMetadataResolver,
          null: true,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          experiment: { milestone: '19.2' },
          description: 'Metadata describing Duo Agent Platform flow capabilities available to the caller.'
        field :ai_foundational_chat_agent, resolver: ::Resolvers::Ai::FoundationalChatAgentResolver,
          null: true,
          description: "Core agent in GitLab.",
          experiment: { milestone: '19.0' }
        field :ai_foundational_chat_agents, resolver: ::Resolvers::Ai::FoundationalChatAgentsResolver,
          null: false,
          description: "Core agents in GitLab.",
          max_page_size: 1_000,
          experiment: { milestone: '18.6' }
        field :ai_usage_data,
          ::Types::Analytics::AiUsage::AiInstanceUsageDataType,
          description: 'Instance level AI-related data. Admins only.',
          resolver_method: :itself,
          experiment: { milestone: '18.7' }
        field :ai_tool_rules,
          resolver: ::Resolvers::Ai::ToolRulesResolver,
          null: true,
          description: 'AI tool governance rules for a namespace.',
          experiment: { milestone: '19.1' }
        field :admin_duo_availability_namespaces,
          resolver: ::Resolvers::Ai::DuoSettings::DuoAvailabilityNamespacesResolver,
          null: true,
          description: 'List groups with their resolved GitLab Duo availability for admin overrides.',
          experiment: { milestone: '19.2' }
        field :blob_search, ::Types::Search::Blob::BlobSearchType,
          null: true,
          resolver: ::Resolvers::Search::Blob::BlobSearchResolver,
          experiment: { milestone: '17.2' },
          description: 'Find code visible to the current user'
        field :ci_minutes_usage, ::Types::Ci::Minutes::NamespaceMonthlyUsageType.connection_type,
          null: true,
          description: 'Compute usage data for a namespace.' do
          argument :namespace_id, ::Types::GlobalIDType[::Namespace],
            required: false,
            description: 'Global ID of the Namespace for the monthly compute usage.'
          argument :date, ::Types::DateType,
            required: false,
            description: 'Date for which to retrieve the usage data, should be the first day of a month.'
        end
        field :ci_minutes_project_monthly_usage,
          ::Types::Ci::Minutes::ProjectMonthlyUsageType.connection_type,
          null: true,
          description: 'Compute usage data for projects in a namespace for a given month. ' \
                       'Returns project usage independent of whether a namespace-level usage record exists.' do
          argument :namespace_id, ::Types::GlobalIDType[::Namespace],
            required: false,
            description: 'Global ID of the Namespace for the project compute usage.'
          argument :date, ::Types::DateType,
            required: false,
            description: 'Date for which to retrieve the usage data, should be the first day of a month. ' \
                         'Defaults to the current month.'
        end
        field :ci_dedicated_hosted_runner_filters, Types::Ci::Minutes::DedicatedRunnerFiltersType,
          null: true,
          fallback_value: {},
          description: 'Returns available filters for GitLab Dedicated runner usage data.'
        field :ci_dedicated_hosted_runner_usage, Types::Ci::Minutes::DedicatedMonthlyUsageType.connection_type,
          null: true,
          resolver: EE::Resolvers::Ci::Minutes::DedicatedMonthlyUsageResolver,
          description: 'Compute usage data for runners across namespaces on GitLab Dedicated. ' \
                       'Defaults to the current year if no year or billing month is specified. ' \
                       'Ultimate only.' do
          argument :billing_month, ::Types::DateType,
            required: false,
            description: 'First day of the month to retrieve data for.'
          argument :year, GraphQL::Types::Int,
            required: false,
            description: 'Year to retrieve data for.'
          argument :grouping,
            type: EE::Types::Ci::Minutes::GroupingEnum,
            required: false,
            description: 'Groups usage data by instance aggregate or root namespace.'
          argument :runner_id, ::Types::GlobalIDType[::Ci::Runner],
            required: false,
            description: 'Runner ID to retrieve data for.'
        end
        field :ai_catalog_configured_items,
          resolver: ::Resolvers::Ai::Catalog::ConfiguredItemsResolver,
          null: false,
          description: 'AI Catalog items configured for use.',
          experiment: { milestone: '18.2' }
        field :ai_catalog_item_consumer,
          resolver: ::Resolvers::Ai::Catalog::ItemConsumerResolver,
          null: true,
          description: 'Find a single AI Catalog item consumer by ID.',
          experiment: { milestone: '18.5' }
        field :ai_catalog_mcp_server,
          resolver: ::Resolvers::Ai::Catalog::McpServerResolver,
          null: true,
          description: 'Find an AI Catalog MCP server by ID.',
          experiment: { milestone: '18.10' }
        field :ai_catalog_mcp_servers,
          resolver: ::Resolvers::Ai::Catalog::McpServersResolver,
          null: false,
          description: 'List of AI Catalog MCP servers.',
          experiment: { milestone: '18.10' }
        field :current_license, ::Types::Admin::CloudLicenses::CurrentLicenseType,
          null: true,
          resolver: ::Resolvers::Admin::CloudLicenses::CurrentLicenseResolver,
          description: 'Fields related to the current license.'
        field :devops_adoption_enabled_namespaces,
          null: true,
          description: 'Get configured DevOps adoption namespaces. **Status**: Beta. This endpoint is subject to ' \
                       'change without notice.',
          resolver: ::Resolvers::Analytics::DevopsAdoption::EnabledNamespacesResolver
        field :orbit, ::Types::Analytics::Orbit::OrbitType,
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          directives: granular_scope_directive(permissions: :read_orbit, boundary: :user, boundary_type: :user),
          description: 'Orbit data of the instance and of the groups of the current user. ' \
            'Returns null when the user is not signed in.',
          experiment: { milestone: '19.4' }
        field :epic_board_list, ::Types::Boards::EpicListType,
          null: true,
          resolver: ::Resolvers::Boards::EpicListResolver
        field :geo_node, ::Types::Geo::GeoNodeType,
          null: true,
          resolver: ::Resolvers::Geo::GeoNodeResolver,
          description: 'Find a Geo node.'
        field :iteration, ::Types::IterationType,
          null: true,
          description: 'Find an iteration.' do
          argument :id, ::Types::GlobalIDType[::Iteration],
            required: true,
            description: 'Find an iteration by its ID.'
        end
        field :instance_security_dashboard, ::Types::InstanceSecurityDashboardType,
          null: true,
          resolver: ::Resolvers::InstanceSecurityDashboardResolver,
          description: 'Fields related to Instance Security Dashboard.'
        field :license_history_entries, ::Types::Admin::CloudLicenses::LicenseHistoryEntryType.connection_type,
          null: true,
          resolver: ::Resolvers::Admin::CloudLicenses::LicenseHistoryEntriesResolver,
          description: 'Fields related to entries in the license history.'
        field :subscription_future_entries, ::Types::Admin::CloudLicenses::SubscriptionFutureEntryType.connection_type,
          null: true,
          resolver: ::Resolvers::Admin::CloudLicenses::SubscriptionFutureEntriesResolver,
          description: 'Fields related to entries in future subscriptions.'
        field :vulnerabilities,
          ::Types::VulnerabilityType.connection_type,
          null: true,
          extras: [:lookahead],
          description: "Vulnerabilities reported on projects on the current user's instance security dashboard.",
          resolver: ::Resolvers::VulnerabilitiesResolver,
          scopes: [:api, :read_api, :ai_workflows]
        field :vulnerabilities_count_by_day,
          ::Types::VulnerabilitiesCountByDayType.connection_type,
          null: true,
          resolver: ::Resolvers::VulnerabilitiesCountPerDayResolver,
          description: "The historical number of vulnerabilities per day for the projects on the current " \
                       "user's instance security dashboard."
        field :vulnerability,
          ::Types::VulnerabilityType,
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          description: "Find a vulnerability." do
          argument :id, ::Types::GlobalIDType[::Vulnerability],
            required: true,
            description: 'Global ID of the Vulnerability.'
        end
        field :dependency,
          ::Types::Sbom::DependencyType,
          null: true,
          description: "Find a dependency." do
          argument :id, ::Types::GlobalIDType[::Sbom::Occurrence],
            required: true,
            description: 'Global ID of the Dependency.'
        end
        field :spdx_licenses,
          resolver: ::Resolvers::Sbom::SpdxLicensesResolver,
          description: 'List of SPDX licenses from the SPDX licence catalogue.',
          experiment: { milestone: '19.1' }
        field :workspace, ::Types::RemoteDevelopment::WorkspaceType,
          null: true,
          description: 'Find a workspace.' do
          argument :id, ::Types::GlobalIDType[::RemoteDevelopment::Workspace],
            required: true,
            description: 'Find a workspace by its ID.'
        end
        field :workspaces,
          ::Types::RemoteDevelopment::WorkspaceType.connection_type,
          null: true,
          resolver: ::Resolvers::RemoteDevelopment::WorkspacesAdminResolver,
          description: 'Find workspaces across the entire instance. This field is only available to instance admins, ' \
                       'it will return an empty result for all non-admins.'
        field :instance_external_audit_event_destinations,
          ::Types::AuditEvents::InstanceExternalAuditEventDestinationType.connection_type,
          null: true,
          description: 'Instance level external audit event destinations.',
          resolver: ::Resolvers::AuditEvents::InstanceExternalAuditEventDestinationsResolver,
          deprecated: { reason: 'Use `auditEventsInstanceStreamingDestinations` instead', milestone: '18.10' }

        field :ai_conversation_threads, ::Types::Ai::Conversations::ThreadType.connection_type,
          resolver: ::Resolvers::Ai::Conversations::ThreadsResolver,
          experiment: { milestone: '17.9' },
          description: 'List conversation threads of AI features.'

        field :ai_messages, ::Types::Ai::MessageType.connection_type,
          resolver: ::Resolvers::Ai::ChatMessagesResolver,
          experiment: { milestone: '16.1' },
          description: 'Find GitLab Duo Chat messages.'

        field :duo_workflow_events, ::Types::Ai::DuoWorkflows::WorkflowEventType.connection_type,
          resolver: ::Resolvers::Ai::DuoWorkflows::WorkflowEventsResolver,
          default_page_size: ::Resolvers::Ai::DuoWorkflows::WorkflowEventsResolver::DEFAULT_EVENTS_PAGE_SIZE,
          max_page_size: ::Resolvers::Ai::DuoWorkflows::WorkflowEventsResolver::MAX_EVENTS_PAGE_SIZE,
          experiment: { milestone: '17.2' },
          description: 'List the events for a Duo Agent Platform. ' \
                       'Returns only the latest checkpoint by default. ' \
                       'Use `first` and `after` to page through history. ' \
                       'Returns at most 5 checkpoints per page.'

        field :duo_workflow_branches, [::Types::Ai::DuoWorkflows::BranchType],
          resolver: ::Resolvers::Ai::DuoWorkflows::WorkflowBranchesResolver,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          experiment: { milestone: '19.3' },
          description: 'The alternative branches to the provided user message. Multiple branches can be created when ' \
            'a user retries a message. Returns an error unless the message is on the current branch of the ' \
            'session. Returns an empty list if the session does not store incremental checkpoints.'

        field :duo_workflow_workflows, ::Types::Ai::DuoWorkflows::WorkflowType.connection_type,
          resolver: ::Resolvers::Ai::DuoWorkflows::WorkflowsResolver,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          description: 'List the workflows owned by the current user.'

        field :duo_workflow_recent_session_projects, [::Types::ProjectType],
          null: true,
          resolver: ::Resolvers::Ai::DuoWorkflows::RecentSessionProjectsResolver,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          experiment: { milestone: '19.5' },
          description: 'Projects the current user has Duo Agent Platform sessions in, ordered by most recent ' \
            'session activity. Not a complete list: limited to the ' \
            "#{::Ai::DuoWorkflows::RecentSessionProjectsFinder::MAX_PROJECTS} most recent projects."

        field :gitlab_credits_available, GraphQL::Types::Boolean,
          null: false,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          resolver: ::Resolvers::Ai::GitlabCreditsAvailableResolver,
          experiment: { milestone: '18.11' },
          description: 'Whether GitLab credits are available for the current user.'

        field :gitlab_credits_unavailable_reason, ::Types::Ai::CreditsDenialReasonEnum,
          null: true,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          resolver: ::Resolvers::Ai::GitlabCreditsUnavailableReasonResolver,
          experiment: { milestone: '19.2' },
          description: 'Reason GitLab credits are unavailable. Returns "usage_billing_forbidden" when usage ' \
            'billing is not available for the account, and "namespace_missing" when there is no ' \
            'namespace to bill the usage to. Returns null when credits are available or the ' \
            'unavailability reason is not recognized.'

        field :duo_default_namespace_candidates, ::Types::NamespaceType.connection_type,
          null: true,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          resolver: ::Resolvers::Ai::DuoDefaultNamespaceCandidatesResolver,
          experiment: { milestone: '18.7' },
          description: "List namespaces suitable to be set as default namespace."

        field :ci_queueing_history,
          ::Types::Ci::QueueingHistoryType,
          null: true,
          description: 'Time taken for CI jobs to be picked up by runner by percentile. ' \
            'Enable the ClickHouse database backend to use this query.',
          resolver: ::Resolvers::Ci::InstanceQueueingHistoryResolver,
          extras: [:lookahead]
        field :runner_usage_by_project,
          [::Types::Ci::RunnerUsageByProjectType],
          null: true,
          description: 'Runner usage by project. Enable the ClickHouse database backend to use this query.',
          resolver: ::Resolvers::Ci::RunnerUsageByProjectResolver
        field :runner_usage,
          [::Types::Ci::RunnerUsageType],
          null: true,
          description: 'Runner usage by runner. Enable the ClickHouse database backend to use this query.',
          resolver: ::Resolvers::Ci::RunnerUsageResolver

        field :instance_google_cloud_logging_configurations,
          ::Types::AuditEvents::Instance::GoogleCloudLoggingConfigurationType.connection_type,
          null: true,
          description: 'Instance level google cloud logging configurations.',
          resolver: ::Resolvers::AuditEvents::Instance::GoogleCloudLoggingConfigurationsResolver,
          deprecated: { reason: 'Use `auditEventsInstanceStreamingDestinations` with `gcpLogging` category instead',
                        milestone: '18.10' }
        field :member_role_permissions,
          ::Types::Members::CustomizableStandardPermissionType.connection_type,
          null: true,
          description: 'List of all standard customizable permissions.',
          experiment: { milestone: '16.4' }
        field :admin_member_role_permissions,
          ::Types::Members::CustomizableAdminPermissionType.connection_type,
          description: 'List of all admin customizable permissions.',
          experiment: { milestone: '17.9' }
        field :member_role, ::Types::MemberRoles::MemberRoleType,
          null: true,
          description: 'Finds a single custom role for the instance. Available only for GitLab Self-Managed.',
          resolver: ::Resolvers::MemberRoles::RolesResolver.single,
          experiment: { milestone: '16.6' }
        field :admin_member_role,
          ::Types::Members::AdminMemberRoleType,
          description: 'Finds a single admin custom role for the instance. Available only for GitLab Self-Managed.',
          resolver: ::Resolvers::Members::AdminRolesResolver.single,
          experiment: { milestone: '17.10' }
        field :standard_role, ::Types::Members::StandardRoleType,
          null: true,
          description: 'Finds a single default role for the instance. Available only for GitLab Self-Managed.',
          resolver: ::Resolvers::Members::StandardRolesResolver.single,
          experiment: { milestone: '17.6' }
        field :standard_roles, ::Types::Members::StandardRoleType.connection_type,
          null: true, description: 'Default roles available for the instance. Available only for GitLab Self-Managed.',
          resolver: ::Resolvers::Members::StandardRolesResolver,
          experiment: { milestone: '17.3' }
        field :self_managed_add_on_eligible_users,
          ::Types::GitlabSubscriptions::AddOnUserType.connection_type,
          null: true,
          description: 'Users within the self-managed instance who are eligible for add-ons.',
          resolver: ::Resolvers::GitlabSubscriptions::SelfManaged::AddOnEligibleUsersResolver,
          experiment: { milestone: '16.7' }
        field :self_managed_users_queued_for_role_promotion,
          EE::Types::GitlabSubscriptions::MemberManagement::UsersQueuedForRolePromotionType.connection_type,
          null: true,
          resolver: ::Resolvers::GitlabSubscriptions::MemberManagement::SelfManaged::
              UsersQueuedForRolePromotionResolver,
          description: 'Fields related to users within a self-managed instance that are pending role ' \
                       'promotion approval.'
        field :audit_events_instance_amazon_s3_configurations,
          ::Types::AuditEvents::Instance::AmazonS3ConfigurationType.connection_type,
          null: true,
          description: 'Instance-level Amazon S3 configurations for audit events.',
          resolver: ::Resolvers::AuditEvents::Instance::AmazonS3ConfigurationsResolver,
          deprecated: { reason: 'Use `auditEventsInstanceStreamingDestinations` with `amazonS3` category instead',
                        milestone: '18.10' }
        field :member_roles, ::Types::MemberRoles::MemberRoleType.connection_type,
          null: true, description: 'Custom roles available for the instance. Available only for GitLab Self-Managed.',
          resolver: ::Resolvers::MemberRoles::RolesResolver,
          experiment: { milestone: '16.7' }
        field :admin_member_roles,
          ::Types::Members::AdminMemberRoleType.connection_type,
          description: 'Admin custom roles available for the instance. Available only for GitLab Self-Managed.',
          resolver: ::Resolvers::Members::AdminRolesResolver,
          experiment: { milestone: '17.10' }
        field :google_cloud_artifact_registry_repository_artifact,
          ::Types::GoogleCloud::ArtifactRegistry::ArtifactDetailsType,
          null: true,
          description: 'Details about an artifact in the Google Artifact Registry.',
          resolver: ::Resolvers::GoogleCloud::ArtifactRegistry::ArtifactResolver,
          experiment: { milestone: '16.10' }
        field :audit_events_instance_streaming_destinations,
          ::Types::AuditEvents::Instance::StreamingDestinationType.connection_type,
          null: true,
          description: 'Instance-level external audit event streaming destinations.',
          resolver: ::Resolvers::AuditEvents::Instance::StreamingDestinationsResolver,
          experiment: { milestone: '16.11' }

        field :ai_self_hosted_models,
          ::Types::Ai::SelfHostedModels::SelfHostedModelType.connection_type,
          null: true,
          resolver: ::Resolvers::Ai::SelfHostedModels::SelfHostedModelsResolver,
          experiment: { milestone: '17.1' },
          description: 'Returns the self-hosted model if an ID is provided, otherwise returns all models.' do
            argument :id, ::Types::GlobalIDType[::Ai::SelfHostedModel],
              required: false,
              description: "Global ID of a self-hosted model."
          end

        field :cloud_connector_status,
          ::Types::CloudConnector::StatusType,
          null: true,
          description: 'Run a series of status checks for Cloud Connector features.',
          resolver: ::Resolvers::CloudConnector::StatusResolver,
          experiment: { milestone: '17.3' }

        field :project_secrets_manager, ::Types::SecretsManagement::ProjectSecretsManagerType,
          null: true,
          experiment: { milestone: '17.4' },
          description: 'Find a project secrets manager.',
          resolver: ::Resolvers::SecretsManagement::ProjectSecretsManagerResolver

        field :project_secrets, ::Types::SecretsManagement::ProjectSecretType.connection_type,
          null: true,
          experiment: { milestone: '17.8' },
          description: 'List project secrets.',
          resolver: ::Resolvers::SecretsManagement::ProjectSecretsResolver

        field :project_secrets_count, GraphQL::Types::Int,
          null: true,
          experiment: { milestone: '18.11' },
          description: 'Total number of secrets in a project.',
          resolver: ::Resolvers::SecretsManagement::ProjectSecretsCountResolver

        field :project_secrets_needing_rotation, ::Types::SecretsManagement::ProjectSecretType.connection_type,
          null: true,
          experiment: { milestone: '18.5' },
          description: 'List project secrets that need to be rotated.',
          resolver: ::Resolvers::SecretsManagement::ProjectSecrets::ListNeedingRotationResolver

        field :project_secret, ::Types::SecretsManagement::ProjectSecretType,
          null: true,
          experiment: { milestone: '17.9' },
          description: 'View a specific project secret.',
          resolver: ::Resolvers::SecretsManagement::ProjectSecretResolver

        field :secret_permissions, ::Types::SecretsManagement::Permissions::SecretPermissionType.connection_type,
          null: true,
          experiment: { milestone: '17.10' },
          description: 'List secret permissions.',
          resolver: ::Resolvers::SecretsManagement::Permissions::SecretPermissionsResolver

        field :project_secrets_permissions, ::Types::SecretsManagement::ProjectSecretsPermissionType.connection_type,
          null: true,
          experiment: { milestone: '18.7' },
          description: 'List project secrets permissions.',
          resolver: ::Resolvers::SecretsManagement::ProjectSecretsPermissionsResolver

        field :group_secrets_manager, ::Types::SecretsManagement::GroupSecretsManagerType,
          null: true,
          experiment: { milestone: '18.6' },
          description: 'Find a group secrets manager.',
          resolver: ::Resolvers::SecretsManagement::GroupSecretsManagerResolver

        field :group_secrets_permissions, ::Types::SecretsManagement::GroupSecretsPermissionType.connection_type,
          null: true,
          experiment: { milestone: '18.7' },
          description: 'List group secrets permissions.',
          resolver: ::Resolvers::SecretsManagement::GroupSecretsPermissionsResolver

        field :group_secrets, ::Types::SecretsManagement::GroupSecretType.connection_type,
          null: true,
          max_page_size: 500,
          experiment: { milestone: '18.9' },
          description: 'List group secrets.',
          resolver: ::Resolvers::SecretsManagement::GroupSecretsResolver

        field :group_secrets_needing_rotation, ::Types::SecretsManagement::GroupSecretType.connection_type,
          null: true,
          experiment: { milestone: '18.10' },
          description: 'List group secrets that need to be rotated.',
          resolver: ::Resolvers::SecretsManagement::GroupSecrets::ListNeedingRotationResolver

        field :group_secret, ::Types::SecretsManagement::GroupSecretType,
          null: true,
          experiment: { milestone: '18.9' },
          description: 'View a specific group secret.',
          resolver: ::Resolvers::SecretsManagement::GroupSecretResolver

        field :group_secrets_count, GraphQL::Types::Int,
          null: true,
          experiment: { milestone: '18.11' },
          description: 'Total number of secrets in a group.',
          resolver: ::Resolvers::SecretsManagement::GroupSecretsCountResolver

        field :namespace_secrets_manager_enrollment,
          ::Types::SecretsManagement::EnrollmentType,
          null: true,
          experiment: { milestone: '19.0' },
          description: 'Check Secrets Manager enrollment for a namespace.',
          resolver: ::Resolvers::SecretsManagement::NamespaceEnrollmentResolver

        field :instance_secrets_manager_enrollment,
          ::Types::SecretsManagement::InstanceEnrollmentType,
          null: true,
          experiment: { milestone: '19.0' },
          description: 'Check if Secrets Manager is enrolled at the instance level.',
          resolver: ::Resolvers::SecretsManagement::InstanceEnrollmentResolver

        field :secrets_manager_instance_entitlement,
          ::Types::SecretsManagement::EntitlementType,
          null: true,
          experiment: { milestone: '19.4' },
          description: 'Instance-wide Secrets Manager entitlement on GitLab Self-Managed. ' \
            'Not available on GitLab.com, where entitlement is per top-level group.',
          resolver: ::Resolvers::SecretsManagement::InstanceEntitlementResolver

        field :ai_feature_settings,
          ::Types::Ai::FeatureSettings::FeatureSettingType.connection_type,
          null: true,
          description: 'List of configurable AI features.',
          resolver: ::Resolvers::Ai::FeatureSettings::FeatureSettingsResolver,
          experiment: { milestone: '17.4' }

        field :ai_slash_commands, [::Types::Ai::SlashCommandType], null: true,
          resolver: ::Resolvers::Ai::SlashCommandsResolver,
          description: 'Get available GitLab Duo Chat slash commands for the current user for a specific URL'

        field :ai_chat_available_models, ::Types::Ai::Chat::AvailableModelsType, null: true,
          resolver: ::Resolvers::Ai::Chat::AvailableModelsResolver,
          description: 'Get available models for Duo Agentic Chat. ' \
            'This field can be resolved only once in any single request.',
          experiment: { milestone: '18.4' } do
          extension(::Gitlab::Graphql::Limit::FieldCallCount, limit: 1)
        end

        field :ai_chat_context_presets, ::Types::Ai::Chat::ContextPresetsType, null: true,
          resolver: ::Resolvers::Ai::Chat::ContextPresetsResolver,
          calls_gitaly: true,
          description: 'Get available GitLab Duo Chat context presets for the current user for a specific URL'

        field :ai_chat_included_projects,
          null: true,
          resolver: ::Resolvers::Ai::Chat::IncludedProjectsResolver,
          description: "Get projects that can be included by the current user in a GitLab Duo Chat context",
          experiment: { milestone: '18.7' }

        field :compliance_framework_templates,
          resolver: ::Resolvers::ComplianceManagement::FrameworkTemplateResolver,
          null: true,
          description: 'List of available compliance framework templates.'

        field :compliance_requirement_controls, ::Types::ComplianceManagement::ComplianceRequirementControlType,
          null: true,
          fallback_value: [],
          description: 'Get the list of all the compliance requirement controls.'

        field :duo_settings, ::Types::Ai::DuoSettings::DuoSettingsType,
          null: true,
          fallback_value: {},
          description: 'Get GitLab Duo settings',
          resolver: ::Resolvers::Ai::DuoSettings::DuoSettingsResolver,
          experiment: { milestone: '17.9' }

        field :ai_domain_settings, GraphQL::Types::String.connection_type,
          null: true,
          description: 'List of allowed or denied domains for AI features.',
          resolver: ::Resolvers::Ai::DomainSettingsResolver,
          experiment: { milestone: '19.0' }

        field :custom_dashboards,
          resolver: ::Resolvers::Analytics::CustomDashboards::DashboardsResolver,
          description: 'Find custom dashboards for an organization.'

        field :custom_dashboard,
          resolver: ::Resolvers::Analytics::CustomDashboards::DashboardResolver,
          description: 'Find a custom dashboard by ID.'

        field :custom_system_dashboard,
          resolver: ::Resolvers::Analytics::CustomDashboards::SystemDashboardResolver,
          description: 'Find a GitLab-provided system dashboard by slug.'

        field :custom_field, ::Types::Issuables::CustomFieldType,
          null: true,
          description: 'Find a custom field by its ID.',
          resolver: ::Resolvers::Issuables::CustomFieldResolver,
          experiment: { milestone: '17.10' },
          directives: granular_scope_directive(
            permissions: :read_custom_field, boundary_argument: :id, boundary: :namespace, boundary_type: :group
          )

        field :ldap_admin_role_links,
          ::Types::Authz::LdapAdminRoleLinkType.connection_type,
          description: 'LDAP admin links. Available only for GitLab Self-Managed.',
          resolver: ::Resolvers::Authz::LdapAdminRoleLinksResolver,
          experiment: { milestone: '17.11' }

        field :ai_model_selection_namespace_settings,
          ::Types::Ai::ModelSelection::Namespaces::FeatureSettingType.connection_type,
          null: true,
          description: 'List of configurable AI features for namespace Model Selection.',
          resolver: ::Resolvers::Ai::ModelSelection::Namespaces::FeatureSettingsResolver,
          experiment: { milestone: '18.1' }

        field :project_compliance_violation,
          ::Types::ComplianceManagement::Projects::ComplianceViolationType,
          null: true,
          description: "Find a project compliance violation." do
          argument :id, ::Types::GlobalIDType[::ComplianceManagement::Projects::ComplianceViolation],
            required: true,
            description: 'Global ID of the project compliance violation.'
        end

        field :virtual_registries_container_registry,
          ::Types::VirtualRegistries::Container::RegistryDetailsType,
          null: true,
          description: 'Find a container virtual registry. ' \
            'Returns null if the `container_virtual_registries` feature flag is disabled.',
          experiment: { milestone: '18.7' } do
          argument :id,
            type: ::Types::GlobalIDType[::VirtualRegistries::Container::Registry],
            required: true,
            description: 'Global ID of the container virtual registry.'
        end

        field :virtual_registries_packages_maven_registry,
          ::Types::VirtualRegistries::Packages::Maven::RegistryDetailsType,
          null: true,
          description: 'Find a Maven virtual registry. ' \
            'Returns null if the `maven_virtual_registry` feature flag is disabled.',
          experiment: { milestone: '18.6' } do
          argument :id,
            type: ::Types::GlobalIDType[::VirtualRegistries::Packages::Maven::Registry],
            required: true,
            description: 'Global ID of the Maven virtual registry.'
        end

        field :namespace_security_projects,
          connection_extension: ::Gitlab::Graphql::Extensions::ExternallyPaginatedArrayExtension,
          null: true,
          description: 'Security-filtered projects for a namespace',
          resolver: ::Resolvers::Security::NamespaceSecurityProjectsResolver

        field :virtual_registries_packages_maven_upstream,
          ::Types::VirtualRegistries::Packages::Maven::UpstreamDetailsType,
          null: true,
          description: 'Find a Maven upstream registry. ' \
            'Returns null if the `maven_virtual_registry` feature flag is disabled.',
          experiment: { milestone: '18.6' } do
          argument :id,
            type: ::Types::GlobalIDType[::VirtualRegistries::Packages::Maven::Upstream],
            required: true,
            description: 'Global ID of the Maven upstream registry.'
        end

        field :virtual_registries_container_upstream,
          ::Types::VirtualRegistries::Container::UpstreamDetailsType,
          null: true,
          description: 'Finds a container upstream registry with details. ' \
            'Returns `null` if the `container_virtual_registries` feature flag is disabled.',
          experiment: { milestone: '18.7' } do
            argument :id,
              type: ::Types::GlobalIDType[::VirtualRegistries::Container::Upstream],
              required: true,
              description: 'Global ID of the container upstream.'
          end

        field :work_item_allowed_statuses, ::Types::WorkItems::StatusType.connection_type,
          null: true,
          description: 'Allowed work item statuses from the root groups the current user belongs to.',
          experiment: { milestone: '18.4' },
          resolver: ::Resolvers::WorkItems::AllowedStatusesResolver,
          directives: granular_scope_directive(
            permissions: :read_work_item, boundary: :user, boundary_type: :user)

        field :work_item_type_icon_definitions, [::Types::WorkItems::IconDefinitionType],
          null: false,
          description: 'Available icon definitions for work item types.',
          experiment: { milestone: '18.10' },
          resolver: ::Resolvers::WorkItems::TypeIconDefinitionsResolver

        field :subscription_usage, ::Types::GitlabSubscriptions::SubscriptionUsageType,
          null: true,
          description: 'Usage data of consumables under the subscription.',
          resolver: ::Resolvers::GitlabSubscriptions::SubscriptionUsageResolver,
          experiment: { milestone: '18.5' }

        field :trial_usage, ::Types::GitlabSubscriptions::TrialUsageType,
          null: true,
          description: 'Usage data for trial subscriptions.',
          resolver: ::Resolvers::GitlabSubscriptions::TrialUsageResolver,
          experiment: { milestone: '18.9' }

        field :openbao_health, GraphQL::Types::Boolean,
          null: false,
          description: 'Check if OpenBao instance is healthy and reachable.',
          resolver: ::Resolvers::SecretsManagement::OpenbaoHealthResolver,
          experiment: { milestone: '18.7' }

        field :security_scan_profile, ::Types::Security::ScanProfileType,
          null: false,
          resolver: ::Resolvers::Security::ScanProfileResolver,
          description: 'Get security scan profile by ID.',
          experiment: { milestone: '18.7' }

        field :security_scan_profile_variables, [::Types::Security::ScanProfiles::VariableType],
          null: true,
          resolver: ::Resolvers::Security::ScanProfileVariablesResolver,
          description: 'Configuration variables a security scan profile of the given type can set.',
          experiment: { milestone: '19.5' }

        field :pipeline_execution_schedule_policy_test_run,
          ::Types::Security::PolicyScheduleTestRunType,
          null: true,
          resolver: ::Resolvers::Security::PolicyScheduleTestRunResolver,
          description: 'Find a pipeline execution schedule policy test run by ID.',
          experiment: { milestone: '18.10' }

        field :package_metadata_advisory, ::Types::PackageMetadata::AdvisoryType,
          null: true,
          resolver: ::Resolvers::PackageMetadata::AdvisoryResolver,
          description: 'Get a package metadata advisory.',
          experiment: { milestone: '18.11' }

        field :package_metadata_advisories, ::Types::PackageMetadata::AdvisoryType.connection_type,
          null: true,
          resolver: ::Resolvers::PackageMetadata::AdvisoriesResolver,
          description: 'Get multiple package metadata advisories.',
          experiment: { milestone: '18.11' }
      end

      def vulnerability(id:)
        ::GitlabSchema.find_by_gid(id)
      end

      def dependency(id:)
        ::GitlabSchema.find_by_gid(id)
      end

      def iteration(id:)
        ::GitlabSchema.find_by_gid(id)
      end

      def workspace(id:)
        unless License.feature_available?(:remote_development)
          # NOTE: Could have `included Gitlab::Graphql::Authorize::AuthorizeResource` and then use
          #       raise_resource_not_available_error!, but didn't want to take the risk to mix that into
          #       the root query type
          # rubocop:disable Graphql/ResourceNotAvailableError -- intentionally not used - see note above
          raise ::Gitlab::Graphql::Errors::ResourceNotAvailable,
            "'remote_development' licensed feature is not available"
          # rubocop:enable Graphql/ResourceNotAvailableError
        end

        ::GitlabSchema.find_by_gid(id)
      end

      def ci_minutes_usage(namespace_id: nil, date: nil)
        root_namespace = find_root_namespace(namespace_id)

        ::Ci::Minutes::NamespaceMonthlyUsage.aggregated_by_month(root_namespace, date: date)
      end

      def ci_minutes_project_monthly_usage(namespace_id: nil, date: nil)
        root_namespace = find_root_namespace(namespace_id)
        return ::Ci::Minutes::ProjectMonthlyUsage.none unless root_namespace

        usage_subject = ::Ci::Minutes::NamespaceMonthlyUsage.new(namespace: root_namespace)
        return ::Ci::Minutes::ProjectMonthlyUsage.none unless Ability.allowed?(current_user, :read_usage, usage_subject)

        date ||= ::Ci::Minutes::NamespaceMonthlyUsage.beginning_of_month
        ::Ci::Minutes::ProjectMonthlyUsage.for_namespace_and_date(root_namespace, date)
      end

      def member_role_permissions
        MemberRole.all_customizable_standard_permissions.keys
      end

      def admin_member_role_permissions
        ::Gitlab::CustomRoles::Definition.admin.keys
      end

      def orbit
        {} if current_user
      end

      def project_compliance_violation(id:)
        ::GitlabSchema.find_by_gid(id)
      end

      def ai_catalog_built_in_tools
        tools = ::Ai::Catalog::BuiltInTool.all.sort_by(&:name)

        # This is temporary until we have a proper solution for feature flagging tools.
        # Tool 78 is the gitlab_api_get tool
        # Tool 79 is the gitlab_graphql tool
        # Issue link: https://gitlab.com/gitlab-org/gitlab/-/issues/584050
        unless ::Feature.enabled?(:use_generic_gitlab_api_tools, current_user)
          tools.reject! do |t|
            [78, 79].include?(t.id)
          end
        end

        # Tool 58 is get_session_context. It is highly coupled to the
        # legacy software development flow and not ready to be selectable when
        # building custom agents in the AI Catalog.
        tools.reject! { |t| t.id == 58 }

        # Tool 104 is post_suggested_reviewers. Its endpoint only accepts the
        # Recommend Reviewers flow's service account, so a custom agent
        # selecting it would get a 403 on every call. It stays catalogued so
        # namespace tool rules can govern it.
        tools.reject! { |t| t.id == 104 }

        tools
      end

      def ai_catalog_mcp_tools
        return [] unless ::Feature.enabled?(:mcp_client, current_user)
        return [] unless ::Ai::Catalog.show_gitlab_mcp_server_tools?(current_user)

        ::Ai::Catalog::McpTool.all.sort_by(&:name).reject(&:unlisted)
      end

      def virtual_registries_container_registry(id:)
        find_container_registry_by_id(id)
      end

      def virtual_registries_packages_maven_registry(id:)
        find_maven_registry_by_id(id)
      end

      def virtual_registries_packages_maven_upstream(id:)
        find_maven_registry_by_id(id)
      end

      def virtual_registries_container_upstream(id:)
        find_container_registry_by_id(id)
      end

      private

      def find_root_namespace(namespace_id)
        return current_user&.namespace unless namespace_id

        namespace = ::Gitlab::Graphql::Lazy.force(::GitlabSchema.find_by_gid(namespace_id))
        return unless namespace&.root?

        namespace
      end

      def find_maven_registry_by_id(id)
        find_virtual_registry_by_gid(id) do |registry_object|
          ::VirtualRegistries::Packages::Maven.virtual_registry_available?(registry_object.group, current_user)
        end
      end

      def find_container_registry_by_id(id)
        find_virtual_registry_by_gid(id) do |registry_object|
          ::VirtualRegistries::Container.virtual_registry_available?(registry_object.group, current_user)
        end
      end

      def find_virtual_registry_by_gid(id)
        ::Gitlab::Graphql::Lazy.with_value(::GitlabSchema.find_by_gid(id)) do |registry_object|
          next unless registry_object&.group

          registry_object if yield(registry_object)
        end
      end
    end
  end
end
