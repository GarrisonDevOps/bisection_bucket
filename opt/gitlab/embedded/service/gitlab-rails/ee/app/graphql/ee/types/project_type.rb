# frozen_string_literal: true

module EE
  module Types
    module ProjectType
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        include ::GitlabSubscriptions::LicensedFeatureAvailability

        field :security_scanners, ::Types::SecurityScanners,
          null: true,
          description: 'Information about security analyzers used in the project.',
          method: :itself

        field :security_training_providers, [::Types::Security::TrainingType],
          null: true,
          description: 'List of security training providers for the project',
          resolver: ::Resolvers::SecurityTrainingProvidersResolver

        field :vulnerability_archives, [::Types::Vulnerabilities::ArchiveType],
          null: true,
          description: 'All vulnerability archives of the project.',
          experiment: { milestone: '17.9' },
          resolver: ::Resolvers::Vulnerabilities::ArchivesResolver

        field :vulnerabilities, ::Types::VulnerabilityType.connection_type,
          null: true,
          extras: [:lookahead],
          description: 'Vulnerabilities reported on the project.',
          resolver: ::Resolvers::VulnerabilitiesResolver,
          scopes: [:api, :read_api, :ai_workflows]

        field :vulnerability_scanners, ::Types::VulnerabilityScannerType.connection_type,
          null: true,
          description: 'Vulnerability scanners reported on the project vulnerabilities.',
          resolver: ::Resolvers::Vulnerabilities::ScannersResolver

        field :vulnerabilities_count_by_day, ::Types::VulnerabilitiesCountByDayType.connection_type,
          null: true,
          description: 'The historical number of vulnerabilities per day for the project.',
          resolver: ::Resolvers::VulnerabilitiesCountPerDayResolver

        field :vulnerability_statistic, ::Types::Security::VulnerabilityStatisticType,
          null: true,
          description: 'Counts for each vulnerability severity in the project.',
          authorize: :read_vulnerability_statistics,
          skip_type_authorization: :read_vulnerability_statistics

        field :vulnerability_severities_count, ::Types::VulnerabilitySeveritiesCountType,
          null: true,
          description: 'Counts for each vulnerability severity in the project.',
          resolver: ::Resolvers::VulnerabilitySeveritiesCountResolver

        field :requirement, ::Types::RequirementsManagement::RequirementType,
          null: true,
          description: 'Find a single requirement.',
          resolver: ::Resolvers::RequirementsManagement::RequirementsResolver.single

        field :requirements, ::Types::RequirementsManagement::RequirementType.connection_type,
          null: true,
          description: 'Find requirements.',
          extras: [:lookahead],
          resolver: ::Resolvers::RequirementsManagement::RequirementsResolver

        field :requirement_states_count, ::Types::RequirementsManagement::RequirementStatesCountType,
          null: true,
          description: 'Number of requirements for the project by their state.'

        field :compliance_frameworks, ::Types::ComplianceManagement::ComplianceFrameworkType.connection_type,
          description: 'Compliance frameworks associated with the project.',
          authorize: :read_compliance_framework,
          null: true do
            argument :sort, ::Types::ComplianceManagement::ComplianceFrameworkSortEnum,
              required: false,
              description: 'Sort compliance frameworks by the criteria.'
          end

        field :merge_request_violations,
          ::Types::ComplianceManagement::MergeRequests::ComplianceViolationType.connection_type,
          null: true,
          description: 'Compliance violations reported on merge requests merged within the project.',
          resolver: ::Resolvers::ComplianceManagement::MergeRequests::ProjectComplianceViolationResolver,
          authorize: :read_compliance_violations_report,
          deprecated: {
            reason: 'Use `Group.projectComplianceViolations` with the `projectId` filter instead',
            milestone: '19.6'
          }

        field :compliance_standards_adherence,
          ::Types::Projects::ComplianceStandards::AdherenceType.connection_type,
          null: true,
          description: 'Compliance standards adherence for the project.',
          resolver: ::Resolvers::Projects::ComplianceStandards::ProjectAdherenceResolver,
          authorize: :read_compliance_adherence_report

        field :compliance_control_status,
          ::Types::ComplianceManagement::ComplianceFramework::ProjectControlStatusType.connection_type,
          null: true,
          description: 'Compliance control statuses for a project.',
          resolver: ::Resolvers::ComplianceManagement::ComplianceFramework::ProjectControlStatusResolver,
          authorize: :read_compliance_adherence_report,
          experiment: { milestone: '17.11' }

        field :compliance_requirement_statuses,
          ::Types::ComplianceManagement::ComplianceFramework::ProjectRequirementStatusType.connection_type,
          null: true,
          description: 'Compliance requirement statuses for a project.',
          resolver: ::Resolvers::ComplianceManagement::ComplianceFramework::ProjectRequirementStatusResolver,
          authorize: :read_compliance_adherence_report,
          experiment: { milestone: '18.0' }

        field :security_dashboard_path, GraphQL::Types::String,
          description: "Path to project's security dashboard.",
          null: true

        field :security_configuration_path, GraphQL::Types::String,
          description: "Path to project's security configuration.",
          null: true

        field :licensed_feature_availability,
          ::Types::GitlabSubscriptions::LicensedFeatureAvailabilityType,
          null: false,
          scopes: [:api, :read_api, :ai_workflows],
          experiment: { milestone: '18.11' },
          description: 'Check whether a licensed feature is available.' do
          argument :feature, ::Types::GitlabSubscriptions::LicensedFeatureEnum,
            required: true,
            description: 'Feature to check availability for (for example, SECURITY_DASHBOARD).'
        end

        field :vulnerability_identifier_search,
          [GraphQL::Types::String],
          resolver: ::Resolvers::Vulnerabilities::IdentifierSearchResolver,
          null: true,
          description: 'Search for vulnerabilities by identifier.'

        field :iterations, ::Types::IterationType.connection_type,
          null: true,
          description: 'Find iterations.',
          resolver: ::Resolvers::IterationsResolver

        field :iteration_cadences, ::Types::Iterations::CadenceType.connection_type,
          null: true,
          description: 'Find iteration cadences.',
          resolver: ::Resolvers::Iterations::CadencesResolver

        field :dast_profile,
          ::Types::Dast::ProfileType,
          null: true,
          resolver: ::Resolvers::AppSec::Dast::ProfileResolver.single,
          calls_gitaly: true,
          description: 'DAST Profile associated with the project.'

        field :dast_profiles,
          ::Types::Dast::ProfileType.connection_type,
          null: true,
          extras: [:lookahead],
          late_extensions: [::Gitlab::Graphql::Project::DastProfileConnectionExtension],
          resolver: ::Resolvers::AppSec::Dast::ProfileResolver,
          calls_gitaly: true,
          description: 'DAST Profiles associated with the project.'

        field :dast_site_profile,
          ::Types::DastSiteProfileType,
          null: true,
          resolver: ::Resolvers::DastSiteProfileResolver.single,
          description: 'DAST Site Profile associated with the project.'

        field :dast_site_profiles,
          ::Types::DastSiteProfileType.connection_type,
          null: true,
          description: 'DAST Site Profiles associated with the project.',
          resolver: ::Resolvers::DastSiteProfileResolver

        field :dast_scanner_profiles,
          ::Types::DastScannerProfileType.connection_type,
          null: true,
          description: 'DAST scanner profiles associated with the project.'

        field :dast_site_validations,
          ::Types::DastSiteValidationType.connection_type,
          null: true,
          resolver: ::Resolvers::DastSiteValidationResolver,
          description: 'DAST Site Validations associated with the project.'

        field :repository_size_excess,
          GraphQL::Types::Float,
          null: true,
          description: 'Size of repository that exceeds the limit in bytes.'

        field :actual_repository_size_limit,
          GraphQL::Types::Float,
          null: true,
          description: 'Size limit for the repository in bytes.'

        field :code_coverage_summary,
          ::Types::Ci::CodeCoverageSummaryType,
          null: true,
          description: 'Code coverage summary associated with the project.',
          resolver: ::Resolvers::Ci::CodeCoverageSummaryResolver

        field :alert_management_payload_fields,
          [::Types::AlertManagement::PayloadAlertFieldType],
          null: true,
          description: 'Extract alert fields from payload for custom mapping.',
          resolver: ::Resolvers::AlertManagement::PayloadAlertFieldResolver

        field :incident_management_oncall_schedules,
          ::Types::IncidentManagement::OncallScheduleType.connection_type,
          null: true,
          description: 'Incident Management On-call schedules of the project.',
          extras: [:lookahead],
          resolver: ::Resolvers::IncidentManagement::OncallScheduleResolver

        field :incident_management_escalation_policies,
          ::Types::IncidentManagement::EscalationPolicyType.connection_type,
          null: true,
          description: 'Incident Management escalation policies of the project.',
          extras: [:lookahead],
          resolver: ::Resolvers::IncidentManagement::EscalationPoliciesResolver

        field :incident_management_escalation_policy,
          ::Types::IncidentManagement::EscalationPolicyType,
          null: true,
          description: 'Incident Management escalation policy of the project.',
          resolver: ::Resolvers::IncidentManagement::EscalationPoliciesResolver.single

        field :api_fuzzing_ci_configuration,
          ::Types::AppSec::Fuzzing::API::CiConfigurationType,
          null: true,
          description: 'API fuzzing configuration for the project. '

        field :corpuses, ::Types::AppSec::Fuzzing::Coverage::CorpusType.connection_type,
          null: true,
          resolver: ::Resolvers::AppSec::Fuzzing::Coverage::CorpusesResolver,
          description: "Find corpuses of the project."

        field :push_rules,
          ::Types::PushRulesType,
          null: true,
          description: "Project's push rules settings.",
          method: :push_rule

        field :path_locks,
          ::Types::PathLockType.connection_type,
          null: true,
          description: "The project's path locks.",
          extras: [:lookahead],
          resolver: ::Resolvers::PathLocksResolver

        field :policy_store, ::Types::Govern::PolicyStoreType,
          null: true,
          resolver: ::Resolvers::Govern::PolicyStoreResolver,
          complexity: 10,
          experiment: { milestone: '19.6' },
          description: 'Policy store catalogs and the policies that apply to the project, read-only. ' \
            "Returns `null` when the policy store experiment is not active for the project's top-level group, " \
            'or for a project in a personal namespace. ' \
            'This field can be resolved for only one project in any single request.' do
          extension(::Gitlab::Graphql::Limit::FieldCallCount, limit: 1)
        end

        field :security_policies,
          ::Types::SecurityOrchestration::SecurityPolicyType.connection_type,
          calls_gitaly: true,
          null: true,
          description: 'All security policies of the project.',
          resolver: ::Resolvers::SecurityOrchestration::SecurityPolicyResolver,
          experiment: { milestone: '18.1' }

        field :dependency_firewall_rule_activity,
          [::Types::Security::DependencyFirewallRuleActivityType],
          null: true,
          calls_gitaly: true,
          authorize: :read_security_orchestration_policies,
          experiment: { milestone: '19.3' },
          resolver: ::Resolvers::Security::DependencyFirewallRuleActivityResolver,
          description: 'Dependency firewall per-rule block and warn activity for the project. ' \
            'Available behind the `dependency_firewall_access` feature flag.'

        field :dependency_firewall_activity_summary,
          ::Types::Security::DependencyFirewallActivitySummaryType,
          null: true,
          authorize: :read_security_orchestration_policies,
          experiment: { milestone: '19.3' },
          resolver: ::Resolvers::Security::DependencyFirewallActivitySummaryResolver,
          description: 'Aggregate dependency firewall activity totals for the project. ' \
            'Available behind the `dependency_firewall_access` feature flag. ' \
            'This field can be resolved for only one project in any single request.' do
          extension(::Gitlab::Graphql::Limit::FieldCallCount, limit: 1)
        end

        field :vulnerability_management_policies,
          ::Types::Security::VulnerabilityManagementPolicyType.connection_type,
          calls_gitaly: true,
          null: true,
          experiment: { milestone: '17.5' },
          description: 'Vulnerability Management Policies of the project.',
          resolver: ::Resolvers::Security::VulnerabilityManagementPolicyResolver

        field :pipeline_execution_policies,
          ::Types::SecurityOrchestration::PipelineExecutionPolicyType.connection_type,
          calls_gitaly: true,
          null: true,
          description: 'Pipeline Execution Policies of the project.',
          resolver: ::Resolvers::SecurityOrchestration::PipelineExecutionPolicyResolver

        field :pipeline_execution_schedule_policies,
          ::Types::SecurityOrchestration::PipelineExecutionSchedulePolicyType.connection_type,
          calls_gitaly: true,
          null: true,
          description: 'Pipeline Execution Schedule Policies of the namespace.',
          resolver: ::Resolvers::SecurityOrchestration::PipelineExecutionSchedulePolicyResolver

        field :scan_execution_policies,
          ::Types::SecurityOrchestration::ScanExecutionPolicyType.connection_type,
          calls_gitaly: true,
          null: true,
          description: 'Scan Execution Policies of the project',
          resolver: ::Resolvers::SecurityOrchestration::ScanExecutionPolicyResolver,
          scopes: [:api, :read_api, :ai_workflows]

        field :scan_result_policies,
          ::Types::SecurityOrchestration::ScanResultPolicyType.connection_type,
          calls_gitaly: true,
          null: true,
          deprecated: { reason: 'Use `approvalPolicies`', milestone: '16.9' },
          description: 'Scan Result Policies of the project',
          resolver: ::Resolvers::SecurityOrchestration::ScanResultPolicyResolver

        field :approval_policies,
          ::Types::SecurityOrchestration::ApprovalPolicyType.connection_type,
          calls_gitaly: true,
          null: true,
          description: 'Approval Policies of the project',
          resolver: ::Resolvers::SecurityOrchestration::ApprovalPolicyResolver

        field :security_policy_project,
          ::Types::ProjectType,
          null: true,
          method: :security_policy_management_project,
          description: 'Security policy project assigned to the project, absent if assigned to a parent group.'

        field :security_policy_project_linked_projects,
          ::Types::ProjectType.connection_type,
          null: true,
          description: 'Projects linked to the project, when used as Security Policy Project.'

        field :security_policy_project_linked_namespaces,
          ::Types::NamespaceType.connection_type,
          null: true,
          description: 'Namespaces linked to the project, when used as Security Policy Project.',
          deprecated: { reason: :renamed, replacement: 'security_policy_project_linked_groups', milestone: '17.4' }

        field :security_policy_project_linked_groups,
          ::Types::GroupType.connection_type,
          null: true,
          description: 'Groups linked to the project, when used as Security Policy Project.',
          resolver: ::Resolvers::Security::SecurityPolicyProjectLinkedGroupsResolver

        field :security_policy_eligible_projects,
          ::Types::ProjectType.connection_type,
          null: true,
          experiment: { milestone: '19.0' },
          description: 'All projects eligible for policy scope selection when this project ' \
                       'is used as a Security Policy Project. Includes projects from root ' \
                       'ancestors of all linked groups.',
          resolver: ::Resolvers::Security::SecurityPolicyEligibleProjectsResolver

        field :security_policy_project_suggestions,
          ::Types::ProjectType.connection_type,
          null: true,
          description: 'Security policy project suggestions',
          resolver: ::Resolvers::SecurityOrchestration::SecurityPolicyProjectSuggestionsResolver

        field :dora,
          ::Types::Analytics::Dora::DoraType,
          null: true,
          method: :itself,
          description: "Project's DORA metrics."

        field :ai_catalog_item,
          ::Types::Ai::Catalog::ItemInterface,
          null: true,
          description: 'AI Catalog item of the project.',
          experiment: { milestone: '18.5' } do
            argument :id,
              ::Types::GlobalIDType[::Ai::Catalog::Item],
              required: true,
              description: 'Global ID of the catalog item to find.'
            argument :show_soft_deleted,
              GraphQL::Types::Boolean,
              required: false,
              default_value: false,
              description: 'Whether to show the item if it has been soft-deleted. Defaults to `false`.'
          end

        field :ai_catalog_items,
          ::Types::Ai::Catalog::ItemInterface.connection_type,
          null: false,
          resolver: ::Resolvers::Ai::Catalog::ProjectItemsResolver,
          description: 'AI Catalog items of the project. ' \
            'This field can be resolved for only one project in any single request.',
          experiment: { milestone: '18.6' } do
            extension(::Gitlab::Graphql::Limit::FieldCallCount, limit: 1)
          end

        field :ai_catalog_item_consumer_for_item,
          null: true,
          resolver: ::Resolvers::Ai::Catalog::ProjectItemConsumerForItemResolver,
          description: 'AI Catalog item configuration for the given item in the project, including a ' \
            "configuration inherited from the project's top-level group. Inherited configurations are only " \
            'included when the `ai_catalog_group_inherited_consumers` feature flag is enabled.',
          experiment: { milestone: '19.0' }

        field :ai_metrics,
          ::Types::Analytics::AiMetrics::NamespaceMetricsType,
          null: true,
          description: 'AI-related metrics.',
          resolver: ::Resolvers::Analytics::AiMetrics::NamespaceMetricsResolver,
          extras: [:lookahead],
          experiment: { milestone: '16.11' }

        field :ai_usage_data,
          ::Types::Analytics::AiUsage::AiUsageDataType,
          description: 'AI-related data.',
          resolver_method: :object,
          experiment: { milestone: '17.5' }

        field :ai_governance_metrics,
          ::Types::Ai::Governance::MetricsType,
          null: true,
          # Each call runs two aggregate queries, so keep it expensive enough
          # that it cannot be fanned out across a projects connection.
          complexity: 10,
          resolver: ::Resolvers::Ai::Governance::MetricsResolver,
          description: 'Aggregated AI governance dashboard metrics. Returns null when the ' \
            '`ai_governance_dashboard` feature flag is disabled.',
          experiment: { milestone: '19.3' }

        field :ai_governance_tool_calls,
          ::Types::Ai::Governance::ToolCallsReportType,
          null: true,
          # Runs one aggregate query, so keep it expensive enough that it cannot
          # be fanned out across a projects connection.
          complexity: 10,
          resolver: ::Resolvers::Ai::Governance::ToolCallsResolver,
          description: 'Top tools invoked by AI agents, with invocation counts. ' \
            'Returns null when the `ai_governance_dashboard` or `ai_governance_tool_calls` feature flag is disabled ' \
            'or when ClickHouse is not enabled.',
          experiment: { milestone: '19.5' }

        field :ai_user_metrics,
          ::Types::Analytics::AiMetrics::UserMetricsType.connection_type,
          null: true,
          description: 'AI-related user metrics.',
          resolver: ::Resolvers::Analytics::AiMetrics::UserMetricsResolver,
          directives: granular_scope_directive(
            permissions: :read_enterprise_ai_analytics, boundary: :itself, boundary_type: :project),
          experiment: { milestone: '17.5' }

        field :analytics,
          ::Types::Analytics::AnalyticsType,
          description: 'Project analytics aggregation endpoints.',
          method: :itself,
          experiment: { milestone: '18.11' }

        field :security_training_urls,
          [::Types::Security::TrainingUrlType],
          null: true,
          description: 'Security training URLs for the enabled training providers of the project.',
          resolver: ::Resolvers::SecurityTrainingUrlsResolver

        field :vulnerability_images,
          type: ::Types::Vulnerabilities::ContainerImageType.connection_type,
          null: true,
          description: 'Container images reported on the project vulnerabilities.',
          resolver: ::Resolvers::Vulnerabilities::ContainerImagesResolver

        field :only_allow_merge_if_all_status_checks_passed, GraphQL::Types::Boolean,
          null: true,
          description: 'Indicates that merges of merge requests should be blocked ' \
                       'unless all status checks have passed.'

        field :security_policy_pipeline_must_succeed, GraphQL::Types::Boolean,
          null: true,
          experiment: { milestone: '18.11' },
          description: 'Indicates that all security policy pipelines must succeed ' \
                       'before merge requests can be merged.'

        field :duo_features_enabled,
          null: true,
          experiment: { milestone: '16.9' },
          description: 'Indicates whether GitLab Duo features are enabled for the project.',
          resolver: ::Resolvers::Projects::DuoFeaturesEnabledResolver

        field :duo_context_exclusion_settings, ::Types::Projects::DuoContextExclusionSettingsType,
          null: true,
          description: 'Settings for excluding files from Duo context.',
          experiment: { milestone: '18.2' },
          scopes: [:api, :read_api, :ai_workflows]

        field :duo_workflow_status_check, ::Types::Ai::DuoWorkflows::EnablementType,
          null: true,
          experiment: { milestone: '17.7' },
          scopes: [:api, :read_api, :ai_workflows],
          description: 'Indicates whether Duo Agent Platform is enabled for the project.'

        # Complexity prices one call of these readiness fields. It is added once per
        # connection, not per node, so FieldCallCount is what bounds the fan-out.
        field :duo_workflow_runner_available, GraphQL::Types::Boolean,
          null: true,
          authorize: :duo_workflow,
          complexity: 10,
          experiment: { milestone: '19.3' },
          description: 'Indicates whether the project has a runner that can pick up GitLab Duo ' \
            'Agent Platform workloads. Resolved on request only, because it queries the ' \
            "project's runners and their managers. " \
            'This field can be resolved for at most 10 projects in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 10
        end

        field :duo_workflow_usable_runner_type, GraphQL::Types::String,
          null: true,
          authorize: :duo_workflow,
          complexity: 10,
          experiment: { milestone: '19.3' },
          description: 'Runner type (instance_type, group_type, or project_type) of the runner ' \
            'that can pick up GitLab Duo Agent Platform workloads, or null when none can. ' \
            'Shares its runner scan with duoWorkflowRunnerAvailable when both are requested. ' \
            'This field can be resolved for at most 10 projects in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 10
        end

        field :duo_mcp_servers_count, GraphQL::Types::Int,
          null: true,
          authorize: :read_ai_catalog_mcp_server,
          complexity: 10,
          experiment: { milestone: '19.4' },
          description: "Number of distinct MCP servers used by the project's configured agents. " \
            "Servers blocked for the project's namespace are not counted. " \
            'Resolved on request only, because it reads the configured agents and their versions. ' \
            'This field can be resolved for at most 10 projects in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 10
        end

        field :duo_mcp_server_names, [GraphQL::Types::String],
          null: true,
          authorize: :read_ai_catalog_mcp_server,
          complexity: 10,
          experiment: { milestone: '19.6' },
          description: "Names of the distinct MCP servers used by the project's configured agents, " \
            "sorted alphabetically. Servers blocked for the project's namespace are not listed. " \
            'Resolved on request only, because it reads the configured ' \
            'agents and their versions. Shares its lookup with duoMcpServersCount when both are requested. ' \
            'This field can be resolved for at most 10 projects in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 10
        end

        field :duo_dependency_bump_breaking_changes_available, GraphQL::Types::Boolean,
          null: true,
          method: :duo_dependency_bump_breaking_changes_available?,
          experiment: { milestone: '19.2' },
          description: 'Indicates whether the GitLab Duo resolve dependency bump breaking changes ' \
            'flow can be triggered for the project.'

        field :duo_workflow_workflows, ::Types::Ai::DuoWorkflows::WorkflowType.connection_type,
          null: true,
          description: 'GitLab Duo Agent Platform flows for a project, for all users (remote flows only).',
          resolver: ::Resolvers::Ai::DuoWorkflows::WorkflowsResolver

        field :duo_workflow_events, ::Types::Ai::DuoWorkflows::WorkflowEventType.connection_type,
          null: true,
          default_page_size: ::Resolvers::Ai::DuoWorkflows::WorkflowEventsResolver::DEFAULT_EVENTS_PAGE_SIZE,
          max_page_size: ::Resolvers::Ai::DuoWorkflows::WorkflowEventsResolver::MAX_EVENTS_PAGE_SIZE,
          description: 'Checkpoints for GitLab Duo Agent Platform flows, for all users (remote flows only). ' \
                       'Returns only the latest checkpoint by default. ' \
                       'Use `first` and `after` to page through history. ' \
                       'Returns at most 5 checkpoints per page.',
          resolver: ::Resolvers::Ai::DuoWorkflows::WorkflowEventsResolver

        field :duo_workflow_session_artifacts,
          ::Types::Ai::DuoWorkflows::SessionArtifactType.connection_type,
          null: true,
          description: 'Duo Agent Platform session artifacts for the project.',
          resolver: ::Resolvers::Ai::DuoWorkflows::ProjectSessionArtifactsResolver,
          authorize: :read_agent_artifacts,
          experiment: { milestone: '19.1' }

        field :ai_agent_identities,
          ::Types::Ai::ExternalAgents::AgentIdentityType.connection_type,
          null: true,
          description: 'External agents connected to the project through the GitLab CLI, most recently synced first. ' \
            'Returns none when the `ai_governance_sessions_api` feature flag is disabled.',
          resolver: ::Resolvers::Ai::ExternalAgents::AgentIdentitiesResolver,
          authorize: :read_agent_artifacts,
          experiment: { milestone: '19.6' }

        field :ai_governance_sessions,
          ::Types::Ai::Governance::SessionType.connection_type,
          null: true,
          description: 'AI sessions for the project, from GitLab Duo and external agents. ' \
            'Returns no sessions when the `ai_governance_sessions_api` feature flag is disabled.',
          resolver: ::Resolvers::Ai::Governance::ProjectSessionsResolver,
          authorize: :read_agent_artifacts,
          experiment: { milestone: '19.5' }

        field :gitlab_subscriptions_preview_billable_user_change,
          ::Types::GitlabSubscriptions::PreviewBillableUserChangeType,
          null: true,
          complexity: 100,
          description: 'Preview Billable User Changes',
          resolver: ::Resolvers::GitlabSubscriptions::PreviewBillableUserChangeResolver

        field :customizable_dashboards, ::Types::Analytics::Dashboards::DashboardType.connection_type,
          description: 'Customizable dashboards for the project.',
          null: true,
          calls_gitaly: true,
          experiment: { milestone: '15.6' },
          resolver: ::Resolvers::Analytics::Dashboards::DashboardsResolver

        field :customizable_dashboard_visualizations, ::Types::Analytics::Dashboards::VisualizationType.connection_type,
          description: 'Visualizations of the project or associated configuration project.',
          null: true,
          calls_gitaly: true,
          experiment: { milestone: '16.1' },
          resolver: ::Resolvers::Analytics::Dashboards::VisualizationsResolver

        field :tracking_key, GraphQL::Types::String,
          null: true,
          description: 'Tracking key assigned to the project.',
          experiment: { milestone: '16.0' },
          authorize: :read_customizable_dashboards

        field :dependencies, ::Types::Sbom::DependencyType.connection_type,
          null: true,
          description: 'Software dependencies used by the project.',
          resolver: ::Resolvers::Sbom::DependenciesResolver

        field :dependency_paths,
          ::Types::Sbom::DependencyPathPage,
          null: true,
          authorize: :read_dependency,
          description: 'Ancestor dependency paths for a dependency used by the project. ' \
            'Returns `null` if `dependency_graph_graphql` feature flag is disabled.',
          resolver: ::Resolvers::Sbom::DependencyPathsResolver,
          experiment: { milestone: '17.10' }

        field :components,
          [::Types::Sbom::ComponentType],
          null: true,
          authorize: :read_dependency,
          description: 'Find software dependencies by name.',
          resolver: ::Resolvers::Sbom::ComponentResolver,
          experiment: { milestone: '17.9' }

        field :component_versions,
          ::Types::Sbom::ComponentVersionType.connection_type,
          null: false,
          authorize: :read_dependency,
          description: 'Find software dependency versions by component name.',
          resolver: ::Resolvers::Sbom::ComponentVersionResolver,
          experiment: { milestone: '17.10' }

        field :merge_requests_disable_committers_approval, GraphQL::Types::Boolean,
          null: false,
          method: :merge_requests_disable_committers_approval?,
          description: 'Indicates that committers of the given merge request cannot approve.'

        field :has_jira_vulnerability_issue_creation_enabled, GraphQL::Types::Boolean,
          null: false,
          resolver_method: :jira_vulnerability_issue_creation_enabled?,
          description: 'Indicates whether Jira issue creation from vulnerabilities is enabled.'

        field :pre_receive_secret_detection_enabled, GraphQL::Types::Boolean,
          null: true,
          description: 'Indicates whether secret push protection is on or not for the project.',
          method: :secret_push_protection_enabled,
          authorize: :read_secret_push_protection_info

        field :secret_push_protection_enabled, GraphQL::Types::Boolean,
          null: true,
          description: 'Indicates whether secret push protection is on or not for the project.',
          authorize: :read_secret_push_protection_info

        field :container_scanning_for_registry_enabled, GraphQL::Types::Boolean,
          null: true,
          description: 'Indicates whether container scanning for registry is enabled or not for the project. ' \
            'Returns `null` if unauthorized.',
          authorize: :read_security_configuration

        field :prevent_merge_without_jira_issue_enabled, GraphQL::Types::Boolean,
          null: false,
          method: :prevent_merge_without_jira_issue?,
          description: 'Indicates if an associated issue from Jira is required.'

        field :dependency_proxy_packages_setting,
          ::Types::DependencyProxy::Packages::SettingType,
          null: true,
          description: 'Packages Dependency Proxy settings for the project. ' \
                       'Requires the packages and dependency proxy to be enabled in the config. ' \
                       'Requires the packages feature to be enabled at the project level. '
        field :member_roles, ::Types::MemberRoles::MemberRoleType.connection_type,
          null: true, description: 'Member roles available for the group.',
          resolver: ::Resolvers::MemberRoles::RolesResolver,
          authorize: :read_member_role,
          skip_type_authorization: :read_member_role,
          experiment: { milestone: '16.5' }

        field :ci_subscriptions_projects,
          type: ::Types::Ci::Subscriptions::ProjectType.connection_type,
          deprecated: { reason: 'Use `ciUpstreamProjectSubscriptions`', milestone: '17.6' },
          method: :upstream_project_subscriptions,
          description: 'Pipeline subscriptions for the project.'

        field :ci_upstream_project_subscriptions,
          type: ::Types::Ci::ProjectSubscriptionType.connection_type,
          method: :upstream_project_subscriptions,
          description: 'Pipeline subscriptions where this project is the downstream project.' \
                       'When an upstream project\'s pipeline completes, a pipeline is triggered ' \
                       'in the downstream project (this project).',
          experiment: { milestone: '17.6' }

        field :ci_subscribed_projects,
          type: ::Types::Ci::Subscriptions::ProjectType.connection_type,
          deprecated: { reason: 'Use `ciDownstreamProjectSubscriptions`', milestone: '17.6' },
          method: :downstream_project_subscriptions,
          description: 'Pipeline subscriptions for projects subscribed to the project.'

        field :ci_downstream_project_subscriptions,
          type: ::Types::Ci::ProjectSubscriptionType.connection_type,
          method: :downstream_project_subscriptions,
          description: 'Pipeline subscriptions where this project is the upstream project.' \
                       'When this project\'s pipeline completes, a pipeline is triggered ' \
                       'in the downstream project.',
          experiment: { milestone: '17.6' }

        field :runner_cloud_provisioning,
          ::Types::Ci::RunnerCloudProvisioningType,
          null: true,
          experiment: { milestone: '16.9' },
          description: 'Information used for provisioning the runner on a cloud provider. ' \
                       'Returns `null` if the GitLab instance is not a SaaS instance.' do
                         argument :provider, ::Types::Ci::RunnerCloudProviderEnum, required: true,
                           description: 'Identifier of the cloud provider.'
                         argument :cloud_project_id, ::Types::GoogleCloud::ProjectType, required: true,
                           description: 'Identifier of the cloud project.'
                       end

        field :google_cloud_artifact_registry_repository,
          ::Types::GoogleCloud::ArtifactRegistry::RepositoryType,
          null: true,
          experiment: { milestone: '16.10' },
          description: 'Google Artifact Registry repository. ' \
                       'Returns `null` if the GitLab instance is not a SaaS instance.'

        field :ai_xray_reports, ::Types::Ai::XrayReportType.connection_type,
          null: false,
          experiment: { milestone: '17.8' },
          description: 'X-ray reports of the project.',
          method: :xray_reports

        field :value_stream_analytics,
          ::Types::Analytics::ValueStreamAnalyticsType,
          description: 'Information about Value Stream Analytics within the project.',
          null: true,
          resolver_method: :object

        field :value_stream_dashboard_usage_overview,
          ::Types::Analytics::ValueStreamDashboard::CountType,
          null: true,
          resolver: ::Resolvers::Projects::Analytics::ValueStreamDashboard::CountResolver,
          description: 'Aggregated usage counts within the project',
          experiment: { milestone: '17.2' }

        field :saved_replies,
          ::Types::Projects::SavedReplyType.connection_type,
          null: true,
          description: 'Saved replies available to the project.'

        field :saved_reply,
          resolver: ::Resolvers::Projects::SavedReplyResolver,
          description: 'Saved reply in the project.'

        field :merge_trains,
          ::Types::MergeTrains::TrainType.connection_type,
          resolver: ::Resolvers::MergeTrains::TrainsResolver,
          description: 'Merge trains available to the project. ',
          experiment: { milestone: '17.1' }

        field :pending_member_approvals,
          EE::Types::GitlabSubscriptions::MemberManagement::MemberApprovalType.connection_type,
          null: true,
          resolver: ::Resolvers::GitlabSubscriptions::MemberManagement::MemberApprovalResolver,
          description: 'Pending member promotions of the project.'

        field :observability_logs_links,
          ::Types::Observability::LogType.connection_type,
          null: true,
          experiment: { milestone: '17.4' },
          description: 'Logs attached to the project.',
          resolver: ::Resolvers::Observability::LogsResolver

        field :observability_metrics_links,
          ::Types::Observability::MetricType.connection_type,
          null: true,
          experiment: { milestone: '17.4' },
          description: 'Metrics attached to the project.',
          resolver: ::Resolvers::Observability::MetricsResolver

        field :observability_traces_links,
          ::Types::Observability::TraceType.connection_type,
          null: true,
          experiment: { milestone: '17.4' },
          description: 'Traces attached to the project.',
          resolver: ::Resolvers::Observability::TracesResolver

        field :component_usages, ::Types::Ci::Catalog::Resources::Components::UsageType.connection_type,
          null: true,
          description: 'Component(s) used by the project.',
          resolver: ::Resolvers::Ci::Catalog::Resources::Components::ProjectUsageResolver

        field :security_exclusions,
          ::Types::Security::ProjectSecurityExclusionType.connection_type,
          null: true,
          experiment: { milestone: '17.4' },
          description: 'Security exclusions of the project.',
          resolver: ::Resolvers::Security::ProjectSecurityExclusionResolver

        field :security_exclusion,
          ::Types::Security::ProjectSecurityExclusionType,
          null: true,
          experiment: { milestone: '17.4' },
          description: 'A single security exclusion of a project.',
          resolver: ::Resolvers::Security::ProjectSecurityExclusionResolver.single

        field :target_branch_rules, ::Types::Projects::TargetBranchRuleType.connection_type,
          null: true,
          description: 'Target branch rules of the project.'

        field :analyzer_statuses, [::Types::Security::AnalyzerProjectStatusType],
          null: true,
          description: 'Status for all analyzers in the project.'

        field :duo_agentic_chat_available, ::GraphQL::Types::Boolean,
          null: true,
          resolver: ::Resolvers::Ai::ProjectAgenticChatAccessResolver,
          experiment: { milestone: '18.1' },
          description: 'User access to Duo agentic Chat feature.'

        field :security_metrics,
          ::Types::Security::SecurityMetricsType,
          null: true,
          description: 'Security metrics.' \
          'This feature is currently under development and not yet available for general use.',
          resolver: ::Resolvers::Security::SecurityMetricsResolver,
          experiment: { milestone: '18.3' }

        field :ai_flow_triggers,
          type: ::Types::Ai::FlowTriggerType.connection_type,
          null: true,
          description: 'AI flow triggers of the project. This field can only be resolved for one project per request.',
          resolver: ::Resolvers::Ai::FlowTriggersResolver,
          experiment: { milestone: '18.3' }

        field :dap_factory_configuration,
          null: true,
          description: 'DAP Software Factory configuration file on the default branch. ' \
            'Null unless the `dap_software_factory` feature flag is enabled for the project or its top-level group. ' \
            'This field can only be resolved for one project in any single request.',
          resolver: ::Resolvers::Ai::DapFactory::ConfigurationResolver,
          experiment: { milestone: '19.6' } do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        field :dap_factory_configuration_validation,
          null: true,
          description: 'Validates DAP Software Factory configuration content against the project, ' \
            'with the same rules Sync uses. Null unless the `dap_software_factory` feature flag is enabled ' \
            'for the project or its top-level group. This field can only be resolved for one project in any ' \
            'single request.',
          resolver: ::Resolvers::Ai::DapFactory::ValidationResolver,
          experiment: { milestone: '19.6' } do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        field :security_attributes,
          ::Types::Security::AttributeType.connection_type,
          null: true,
          description: 'Security attributes linked to the project.',
          resolver: ::Resolvers::Security::AttributesResolver,
          experiment: { milestone: '18.5' }

        field :security_scan_profiles,
          type: [::Types::Security::ScanProfileType],
          null: true,
          description: 'Security scan profiles attached to the project.',
          authorize: :read_security_scan_profiles,
          experiment: { milestone: '18.7' },
          scopes: [:api, :read_api, :ai_workflows]

        field :triage_and_remediation_coverage,
          ::Types::Security::TriageAndRemediationCoverageType,
          null: true,
          authorize: :read_security_scan_profiles,
          experiment: { milestone: '19.5' },
          description: 'Triage and remediation capability coverage for the project.'

        field :scan_profile_statuses,
          type: [::Types::Security::ScanProfileProjectStatusType],
          null: true,
          resolver: ::Resolvers::Security::ScanProfileProjectStatusesResolver,
          description: 'Scan profile statuses for the project.',
          authorize: :read_security_scan_profiles,
          experiment: { milestone: '19.0' }

        field :security_tracked_refs,
          ::Types::Security::TrackedRefType.connection_type,
          null: true,
          max_page_size: 20,
          description: 'Refs tracked for security vulnerabilities.',
          resolver: ::Resolvers::Security::TrackedRefsResolver,
          experiment: { milestone: '18.8' }

        field :dependency_tracked_refs,
          ::Types::Sbom::DependencyTrackedRefType.connection_type,
          null: true,
          max_page_size: 20,
          description: 'Refs (branches or tags) where a software dependency appears.',
          resolver: ::Resolvers::Sbom::DependencyTrackedRefsResolver,
          experiment: { milestone: '19.3' }

        field :web_based_commit_signing_enabled,
          GraphQL::Types::Boolean,
          null: false,
          description: 'Indicates whether web-based commit signing is enabled for the project.',
          experiment: { milestone: '18.9' }

        field :ascp_scans,
          ::Types::Security::Ascp::ScanType.connection_type,
          null: true,
          description: 'ASCP security scans for this project.',
          resolver: ::Resolvers::Security::Ascp::ScansResolver,
          experiment: { milestone: '18.10' }

        field :ascp_components,
          ::Types::Security::Ascp::ComponentType.connection_type,
          null: true,
          description: 'ASCP business components in the project.',
          resolver: ::Resolvers::Security::Ascp::ComponentsResolver,
          experiment: { milestone: '18.11' }

        field :merge_request_title_regex, GraphQL::Types::String,
          null: true,
          description: 'Regex used to validate the title of merge requests.'

        field :merge_request_title_regex_description, GraphQL::Types::String,
          null: true,
          description: 'Description of the regex used to validate the title of merge requests.'

        field :vulnerability_workflow_execution,
          resolver: ::Resolvers::Vulnerabilities::VulnerabilityWorkflowExecutionResolver,
          description: 'Returns a vulnerability workflow execution.'

        field :orbit,
          resolver: ::Resolvers::Analytics::Orbit::NamespaceResolver,
          directives: granular_scope_directive(permissions: :read_orbit, boundary: :user, boundary_type: :user),
          scopes: ::Types::Analytics::Orbit::AI_WORKFLOW_SCOPES,
          description: 'Orbit data of the project.',
          experiment: { milestone: '19.5' }
      end

      def tracking_key
        return unless object.product_analytics_enabled?

        object.project_setting.product_analytics_instrumentation_key
      end

      def secret_push_protection_enabled
        object.security_setting.secret_push_protection_enabled
      end

      def jira_vulnerability_issue_creation_enabled?
        object.jira_integration&.configured_to_create_issues_from_vulnerabilities? || false
      end

      def api_fuzzing_ci_configuration
        return unless Ability.allowed?(current_user, :read_security_resource, object)

        configuration = ::AppSec::Fuzzing::API::CiConfiguration.new(project: object)

        {
          scan_modes: ::AppSec::Fuzzing::API::CiConfiguration::SCAN_MODES,
          scan_profiles: configuration.scan_profiles
        }
      end

      def dast_scanner_profiles
        DastScannerProfilesFinder.new(project_ids: [object.id]).execute
      end

      def security_scan_profiles
        # Expose the project to nested types via scoped context so ScanProfiles::ConfigurationType
        # can compute the effective configuration for this project (e.g. the Duo dependency-bump
        # upgrade-policy override, which only applies when a project is known).
        context.scoped_set!(:scan_profile_project, object)

        # Preload triggers and their configurations so ScanProfileType#trigger_settings and
        # #configuration don't N+1 (this field has no lookahead-based preloading).
        profiles = object.security_scan_profiles.not_deleted.with_trigger_configurations
        # Hide attached flow-backed profiles while their flag is off, like ScanProfilesResolver.
        profiles = profiles.not_business_logic unless business_logic_scan_profiles_enabled?
        profiles = profiles.not_skillguard unless ::Feature.enabled?(:skillguard_analyzer, object.root_ancestor)
        profiles
      end

      # Flow availability belongs to the root namespace and is shared by its projects: resolve it once per batch.
      def triage_and_remediation_coverage
        BatchLoader::GraphQL.for(object).batch do |projects, loader|
          capabilities_by_project_id = ::Security::TriageCoverage::ProjectCapabilities.for_projects(projects)

          projects.each do |project|
            loader.call(project, ::Types::Security::TriageAndRemediationCoverageType::Adapter.new(
              capabilities: capabilities_by_project_id.fetch(project.id), project: project
            ))
          end
        end
      end

      def requirement_states_count
        return unless Ability.allowed?(current_user, :read_requirement, object)

        object.requirements.counts_by_state
      end

      def security_dashboard_path
        Rails.application.routes.url_helpers.project_security_dashboard_index_path(object)
      end

      def security_configuration_path
        Rails.application.routes.url_helpers.project_security_configuration_path(object)
      end

      def compliance_frameworks(sort: nil)
        BatchLoader::GraphQL.for(object.id).batch(default_value: []) do |project_ids, loader|
          results = ::ComplianceManagement::Framework.with_projects(project_ids).sort_by_attribute(sort)

          results.each do |framework|
            framework.project_ids.each do |project_id|
              loader.call(project_id) { |xs| xs << framework }
            end
          end
        end
      end

      def runner_cloud_provisioning(provider:, cloud_project_id:)
        {
          container: project,
          provider: provider,
          cloud_project_id: cloud_project_id
        }
      end

      def google_cloud_artifact_registry_repository
        return unless ::Gitlab::Saas.feature_available?(:google_cloud_support)

        project
      end

      def duo_workflow_status_check
        ::Ai::DuoWorkflows::EnablementCheckService.new(project: object, current_user: current_user).execute
      end

      def duo_workflow_runner_available
        duo_project_readiness.runner_available?
      end

      def duo_workflow_usable_runner_type
        duo_project_readiness.usable_runner_type
      end

      def duo_mcp_servers_count
        duo_project_readiness.mcp_servers_count
      end

      def duo_mcp_server_names
        duo_project_readiness.mcp_server_names
      end

      # One readiness instance per type instance, so requesting both runner fields
      # runs the runner scan once.
      def duo_project_readiness
        @duo_project_readiness ||= ::Ai::DuoWorkflow::ProjectReadiness.new(object, current_user)
      end

      def vulnerability_statistic
        return unless object.licensed_feature_available?(:security_inventory)

        object.vulnerability_statistic
      end

      def analyzer_statuses
        BatchLoader::GraphQL.for(object).batch do |projects, loader|
          namespaces = projects.map(&:project_namespace).uniq

          ::Namespaces::Preloaders::NamespaceRootAncestorPreloader.new(namespaces).execute if namespaces.present?

          projects.each do |project|
            next loader.call(project, nil) unless project.licensed_feature_available?(:security_inventory)

            loader.call(project, project.analyzer_statuses)
          end
        end
      end

      def ai_catalog_item(id:, show_soft_deleted:)
        ::Gitlab::Graphql::Lazy.with_value(find_object(id: id)) do |item|
          next unless item && item.project_id == project.id
          next if item.deleted? && show_soft_deleted == false

          item
        end
      end

      override :container_protection_tag_rules
      def container_protection_tag_rules
        return super unless object.licensed_feature_available?(:container_registry_immutable_tag_rules)

        # mutable tag rules come first before immutable
        super + object.container_registry_protection_tag_rules.immutable
      end

      def security_policy_pipeline_must_succeed
        return unless ::Feature.enabled?(:security_policy_pipeline_check, object)
        return unless ::Security::PolicyAvailability.available?(object, :security_orchestration_policies)

        object.security_policy_pipeline_must_succeed
      end

      # Cached per root group: the check can read the root group's namespace_settings, shared by its projects.
      def business_logic_scan_profiles_enabled?
        root_ancestor = object.root_ancestor
        cache = context[:business_logic_scan_profiles_enabled] ||= {}
        return cache[root_ancestor.id] if cache.key?(root_ancestor.id)

        cache[root_ancestor.id] = ::Ai::Catalog::FoundationalFlow::BlSecurity::Definition
          .scan_profiles_enabled_for?(root_ancestor)
      end
      # Not a `private` section: a field method added below one would silently resolve off the model instead.
      private :business_logic_scan_profiles_enabled?
    end
  end
end
