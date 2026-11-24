# frozen_string_literal: true

module EE
  module Types
    module MutationType
      extend ActiveSupport::Concern

      prepended do
        def self.authorization_scopes
          super + [:ai_features, :ai_workflows]
        end

        mount_mutation ::Mutations::Ai::Catalog::Agent::Create, experiment: { milestone: '18.2' }
        mount_mutation ::Mutations::Ai::Catalog::Agent::Delete, experiment: { milestone: '18.2' }
        mount_mutation ::Mutations::Ai::Catalog::Agent::Update, experiment: { milestone: '18.3' }
        mount_mutation ::Mutations::Ai::Catalog::Flow::Create, experiment: { milestone: '18.3' }
        mount_mutation ::Mutations::Ai::Catalog::Flow::Delete, experiment: { milestone: '18.3' }
        mount_mutation ::Mutations::Ai::Catalog::Flow::Update, experiment: { milestone: '18.3' }
        mount_mutation ::Mutations::Ai::Catalog::ItemConsumer::BulkCreate, experiment: { milestone: '19.1' }
        mount_mutation ::Mutations::Ai::Catalog::ItemConsumer::Create, experiment: { milestone: '18.3' }
        mount_mutation ::Mutations::Ai::Catalog::ItemConsumer::Delete, experiment: { milestone: '18.3' }
        mount_mutation ::Mutations::Ai::Catalog::ItemConsumer::Update, experiment: { milestone: '18.3' }
        mount_mutation ::Mutations::Ai::Catalog::ItemVersion::Restore, experiment: { milestone: '19.1' }
        mount_mutation ::Mutations::Ai::Catalog::Item::Star, experiment: { milestone: '18.11' }
        mount_mutation ::Mutations::Ai::Catalog::ItemReport, experiment: { milestone: '18.7' }
        mount_mutation ::Mutations::Ai::Catalog::McpServer::Create, experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::Ai::Catalog::McpServer::Update, experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::Ai::Catalog::McpServer::SetBlock, experiment: { milestone: '19.3' }
        mount_mutation ::Mutations::Ai::Catalog::ThirdPartyFlow::Create, experiment: { milestone: '18.5' }
        mount_mutation ::Mutations::Ai::Catalog::ThirdPartyFlow::Update, experiment: { milestone: '18.5' }
        mount_mutation ::Mutations::Ai::Catalog::ThirdPartyFlow::Delete, experiment: { milestone: '18.5' }
        mount_mutation ::Mutations::Ai::FlowTriggers::Create, experiment: { milestone: '18.3' }
        mount_mutation ::Mutations::Ai::FlowTriggers::Update, experiment: { milestone: '18.3' }
        mount_mutation ::Mutations::Ai::FlowTriggers::Delete, experiment: { milestone: '18.3' }
        mount_mutation ::Mutations::Ai::FlowSchedules::Create, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::Ai::FlowSchedules::Update, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::Ai::FlowSchedules::Delete, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::Ai::UpdateAiToolRule, experiment: { milestone: '19.1' }
        mount_mutation ::Mutations::Ai::BulkUpdateAiToolRules, experiment: { milestone: '19.1' }
        mount_mutation ::Mutations::Ai::Compliance::Anthropic::Integrations::Create, experiment: { milestone: '19.6' }
        mount_mutation ::Mutations::Ai::Compliance::Anthropic::Integrations::Update, experiment: { milestone: '19.6' }
        mount_mutation ::Mutations::Ai::Compliance::Anthropic::Integrations::Delete, experiment: { milestone: '19.6' }
        mount_mutation ::Mutations::Cd::Applications::Create, experiment: { milestone: '19.1' }
        mount_mutation ::Mutations::Cd::Applications::Update, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::Cd::Environments::Create, experiment: { milestone: '19.1' }
        mount_mutation ::Mutations::Cd::Environments::Update, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::Cd::EnvironmentDriverBindings::Create, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::Cd::Services::Create, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::Cd::Services::Update, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::Cd::ArtifactSources::Create, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::Cd::Versions::Create, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::Cd::VersionSets::Create, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::Cd::ApplicationFlowDefinitions::Create, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::Cd::Rollouts::Create, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::Cd::Rollouts::ResolveGate, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::Cd::ApplicationLinks::Create, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::Cd::ApplicationLinks::Update, experiment: { milestone: '19.3' }
        mount_mutation ::Mutations::Cd::ApplicationLinks::Delete, experiment: { milestone: '19.3' }
        mount_mutation ::Mutations::Ci::ProjectSubscriptions::Create
        mount_mutation ::Mutations::Ci::ProjectSubscriptions::Delete
        mount_mutation ::Mutations::Clusters::AgentUrlConfigurations::Create
        mount_mutation ::Mutations::Clusters::AgentUrlConfigurations::Delete
        mount_mutation ::Mutations::ComplianceManagement::Frameworks::Destroy
        mount_mutation ::Mutations::ComplianceManagement::Frameworks::Update
        mount_mutation ::Mutations::ComplianceManagement::Frameworks::Create
        mount_mutation ::Mutations::ComplianceManagement::Frameworks::CreateFromTemplate,
          experiment: { milestone: '19.0' }
        mount_mutation ::Mutations::Issuables::CustomFields::Create, experiment: { milestone: '17.6' }
        mount_mutation ::Mutations::Issuables::CustomFields::Update, experiment: { milestone: '17.6' }
        mount_mutation ::Mutations::Issuables::CustomFields::Archive, experiment: { milestone: '17.9' }
        mount_mutation ::Mutations::Issuables::CustomFields::Unarchive, experiment: { milestone: '17.9' }
        mount_mutation ::Mutations::Issues::SetIteration
        mount_mutation ::Mutations::Issues::SetWeight
        mount_mutation ::Mutations::Issues::SetEpic,
          deprecated: { reason: 'Replaced by WorkItem type', milestone: '17.5' }
        mount_mutation ::Mutations::Issues::SetEscalationPolicy
        mount_mutation ::Mutations::Issues::PromoteToEpic,
          deprecated: {
            reason: 'Replaced by `WorkItem` type. For more information, see [migration guide](https://docs.gitlab.com/api/graphql/epic_work_items_api_migration_guide/)',
            milestone: '17.5'
          }
        mount_mutation ::Mutations::EpicTree::Reorder,
          deprecated: { reason: 'Replaced by WorkItem type', milestone: '17.5' }
        mount_mutation ::Mutations::Epics::Update,
          deprecated: {
            reason: 'Replaced by `WorkItem` type. For more information, see [migration guide](https://docs.gitlab.com/api/graphql/epic_work_items_api_migration_guide/)',
            milestone: '17.5'
          }
        mount_mutation ::Mutations::Epics::Create,
          deprecated: {
            reason: 'Replaced by `WorkItem` type. For more information, see [migration guide](https://docs.gitlab.com/api/graphql/epic_work_items_api_migration_guide/)',
            milestone: '17.5'
          }
        mount_mutation ::Mutations::Epics::SetSubscription,
          deprecated: {
            reason: 'Replaced by `WorkItem` type. For more information, see [migration guide](https://docs.gitlab.com/api/graphql/epic_work_items_api_migration_guide/)',
            milestone: '17.5'
          }
        mount_mutation ::Mutations::Epics::AddIssue,
          deprecated: {
            reason: 'Replaced by `WorkItem` type. For more information, see [migration guide](https://docs.gitlab.com/api/graphql/epic_work_items_api_migration_guide/)',
            milestone: '17.5'
          }
        mount_mutation ::Mutations::Geo::Registries::Update, experiment: { milestone: '16.1' }
        mount_mutation ::Mutations::Geo::Registries::BulkUpdate, experiment: { milestone: '16.4' }
        mount_mutation ::Mutations::GitlabSubscriptions::Activate
        mount_mutation ::Mutations::GitlabSubscriptions::MemberManagement::ProcessUserBillablePromotionRequest,
          experiment: { milestone: '17.2' }
        mount_mutation ::Mutations::GitlabSubscriptions::UserAddOnAssignments::Create
        mount_mutation ::Mutations::GitlabSubscriptions::UserAddOnAssignments::Remove
        mount_mutation ::Mutations::GitlabSubscriptions::UserAddOnAssignments::BulkCreate
        mount_mutation ::Mutations::GitlabSubscriptions::UserAddOnAssignments::BulkRemove
        mount_mutation ::Mutations::GitlabSubscriptions::BudgetCaps::UpsertFlatUserCap
        mount_mutation ::Mutations::GitlabSubscriptions::BudgetCaps::UpsertUserOverrides
        mount_mutation ::Mutations::Govern::PolicyCreate, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::Govern::PolicyDelete, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::Govern::PolicyUpdate, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::Projects::SetLocked
        mount_mutation ::Mutations::Iterations::Create
        mount_mutation ::Mutations::Iterations::Update
        mount_mutation ::Mutations::Iterations::Delete
        mount_mutation ::Mutations::Iterations::Cadences::Create
        mount_mutation ::Mutations::Iterations::Cadences::Update
        mount_mutation ::Mutations::Iterations::Cadences::Destroy
        mount_mutation ::Mutations::MemberRoles::Update
        mount_mutation ::Mutations::MemberRoles::Create, experiment: { milestone: '16.5' }
        mount_mutation ::Mutations::MemberRoles::Admin::Create, experiment: { milestone: '17.7' }
        mount_mutation ::Mutations::MemberRoles::Admin::Update, experiment: { milestone: '17.10' }
        mount_mutation ::Mutations::MemberRoles::Admin::Delete, experiment: { milestone: '17.10' }
        mount_mutation ::Mutations::MemberRoles::Delete, experiment: { milestone: '16.7' }
        mount_mutation ::Mutations::Namespaces::VerifiedNamespace::Create
        mount_mutation ::Mutations::RequirementsManagement::CreateRequirement
        mount_mutation ::Mutations::RequirementsManagement::ExportRequirements
        mount_mutation ::Mutations::RequirementsManagement::UpdateRequirement
        mount_mutation ::Mutations::SecretsManagement::GroupSecretsManagers::Initialize
        mount_mutation ::Mutations::SecretsManagement::GroupSecretsManagers::Deprovision
        mount_mutation ::Mutations::SecretsManagement::GroupSecretsPermissions::Update
        mount_mutation ::Mutations::SecretsManagement::GroupSecretsPermissions::Delete
        mount_mutation ::Mutations::SecretsManagement::GroupSecrets::Create
        mount_mutation ::Mutations::SecretsManagement::GroupSecrets::Update
        mount_mutation ::Mutations::SecretsManagement::GroupSecrets::Delete
        mount_mutation ::Mutations::SecretsManagement::ProjectSecretsManagers::Initialize
        mount_mutation ::Mutations::SecretsManagement::ProjectSecretsManagers::Deprovision
        mount_mutation ::Mutations::SecretsManagement::ProjectSecrets::Create
        mount_mutation ::Mutations::SecretsManagement::ProjectSecrets::CreateFromLeakedToken
        mount_mutation ::Mutations::SecretsManagement::ProjectSecrets::Delete
        mount_mutation ::Mutations::SecretsManagement::ProjectSecrets::Update
        mount_mutation ::Mutations::SecretsManagement::ProjectSecretsPermissions::Update
        mount_mutation ::Mutations::SecretsManagement::ProjectSecretsPermissions::Delete
        mount_mutation ::Mutations::SecretsManagement::StartTrial, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::SecretsManagement::InstanceStartTrial, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::SecretsManagement::EnableAddOn, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::SecretsManagement::InstanceEnableAddOn, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::SecretsManagement::RefreshEntitlement, experiment: { milestone: '19.5' }
        mount_mutation ::Mutations::SecretsManagement::InstanceRefreshEntitlement, experiment: { milestone: '19.5' }
        mount_mutation ::Mutations::SecretsManagement::Enrollment::NamespaceEnroll
        mount_mutation ::Mutations::SecretsManagement::Enrollment::NamespaceUnenroll
        mount_mutation ::Mutations::SecretsManagement::Enrollment::InstanceEnroll
        mount_mutation ::Mutations::SecretsManagement::Enrollment::InstanceUnenroll
        mount_mutation ::Mutations::Security::AiFlowFeedbackCreate, experiment: { milestone: '19.6' }
        mount_mutation ::Mutations::Security::UpdateTrackedContextQuota, experiment: { milestone: '19.6' }
        mount_mutation ::Mutations::Security::Finding::Confirm
        mount_mutation ::Mutations::Security::Finding::CreateIssue
        mount_mutation ::Mutations::Security::Finding::CreateExternalIssueLink
        mount_mutation ::Mutations::Security::Finding::CreateJiraIssueFormUrl, experiment: { milestone: '18.7' }
        mount_mutation ::Mutations::Security::Finding::CreateMergeRequest
        mount_mutation ::Mutations::Security::Finding::CreateVulnerability, experiment: { milestone: '17.5' }
        mount_mutation ::Mutations::Security::Finding::Dismiss
        mount_mutation ::Mutations::Security::Finding::RefreshFindingTokenStatus
        mount_mutation ::Mutations::Security::Finding::RefreshSecurityFindingTokenStatus
        mount_mutation ::Mutations::Security::Finding::Resolve
        mount_mutation ::Mutations::Security::Finding::RevertToDetected
        mount_mutation ::Mutations::Security::Finding::SeverityOverride
        mount_mutation ::Mutations::Security::ProjectTrackedContexts::Create, experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::Security::ProjectTrackedContexts::Destroy, experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::Vulnerabilities::Archival::Archive, experiment: { milestone: '17.10' }
        mount_mutation ::Mutations::Vulnerabilities::Create
        mount_mutation ::Mutations::Vulnerabilities::BulkDismiss
        mount_mutation ::Mutations::Vulnerabilities::RemoveAllFromProject
        mount_mutation ::Mutations::Vulnerabilities::Dismiss, scopes: [:api, :ai_workflows]
        mount_mutation ::Mutations::Vulnerabilities::Resolve
        mount_mutation ::Mutations::Vulnerabilities::Confirm, scopes: [:api, :ai_workflows]
        mount_mutation ::Mutations::Vulnerabilities::RevertToDetected, scopes: [:api, :ai_workflows]
        mount_mutation ::Mutations::Vulnerabilities::CreateIssueLink, scopes: [:api, :ai_workflows]
        mount_mutation ::Mutations::Vulnerabilities::CreateExternalIssueLink
        mount_mutation ::Mutations::Vulnerabilities::DestroyExternalIssueLink
        mount_mutation ::Mutations::Vulnerabilities::LinkMergeRequest, scopes: [:api, :ai_workflows],
          experiment: { milestone: '18.4' }
        mount_mutation ::Mutations::Vulnerabilities::UnlinkMergeRequest, scopes: [:api, :ai_workflows],
          experiment: { milestone: '18.5' }
        mount_mutation ::Mutations::Vulnerabilities::BulkSeverityOverride, scopes: [:api, :ai_workflows]
        mount_mutation ::Mutations::Vulnerabilities::CreateIssue, experiment: { milestone: '17.9' },
          scopes: [:api, :ai_workflows]
        mount_mutation ::Mutations::Vulnerabilities::RefreshVulnerabilityFindingTokenStatus
        mount_mutation ::Mutations::Vulnerabilities::AutoRemediation, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::Vulnerabilities::DismissFalsePositiveFlag, experiment: { milestone: '18.6' }
        mount_mutation ::Mutations::Vulnerabilities::BulkSetVulnerabilityFindingsDueDates
        mount_mutation ::Mutations::Boards::UpdateEpicUserPreferences,
          deprecated: { reason: 'Replaced by WorkItem type', milestone: '17.5' }
        mount_mutation ::Mutations::Boards::EpicBoards::Create,
          deprecated: { reason: 'Replaced by WorkItem type', milestone: '17.5' }
        mount_mutation ::Mutations::Boards::EpicBoards::Destroy,
          deprecated: { reason: 'Replaced by WorkItem type', milestone: '17.5' }
        mount_mutation ::Mutations::Boards::EpicBoards::EpicMoveList,
          deprecated: { reason: 'Replaced by WorkItem type', milestone: '17.5' }
        mount_mutation ::Mutations::Boards::EpicBoards::Update,
          deprecated: { reason: 'Replaced by WorkItem type', milestone: '17.5' }
        mount_mutation ::Mutations::Boards::EpicLists::Create,
          deprecated: { reason: 'Replaced by WorkItem type', milestone: '17.5' }
        mount_mutation ::Mutations::Boards::EpicLists::Destroy,
          deprecated: { reason: 'Replaced by WorkItem type', milestone: '17.5' }
        mount_mutation ::Mutations::Boards::EpicLists::Update,
          deprecated: { reason: 'Replaced by WorkItem type', milestone: '17.5' }
        mount_mutation ::Mutations::Boards::Epics::Create,
          deprecated: { reason: 'Replaced by WorkItem type', milestone: '17.5' }
        mount_mutation ::Mutations::Boards::Lists::UpdateLimitMetrics
        mount_mutation ::Mutations::BranchRules::ExternalStatusChecks::Create, experiment: { milestone: '16.11' }
        mount_mutation ::Mutations::BranchRules::ExternalStatusChecks::Update, experiment: { milestone: '17.0' }
        mount_mutation ::Mutations::BranchRules::ExternalStatusChecks::Destroy, experiment: { milestone: '17.0' }
        mount_mutation ::Mutations::Projects::BranchRules::SquashOptions::Create, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::Projects::BranchRules::SquashOptions::Delete, experiment: { milestone: '17.9' }
        mount_mutation ::Mutations::InstanceSecurityDashboard::AddProject
        mount_mutation ::Mutations::InstanceSecurityDashboard::RemoveProject
        mount_mutation ::Mutations::DastOnDemandScans::Create
        mount_mutation ::Mutations::Dast::Profiles::Create
        mount_mutation ::Mutations::Dast::Profiles::Update
        mount_mutation ::Mutations::Dast::Profiles::Delete
        mount_mutation ::Mutations::Dast::Profiles::Run
        mount_mutation ::Mutations::DastSiteProfiles::Create
        mount_mutation ::Mutations::DastSiteProfiles::Update
        mount_mutation ::Mutations::DastSiteProfiles::Delete
        mount_mutation ::Mutations::DastSiteValidations::Create
        mount_mutation ::Mutations::DastSiteValidations::Revoke
        mount_mutation ::Mutations::DastScannerProfiles::Create
        mount_mutation ::Mutations::DastScannerProfiles::Update
        mount_mutation ::Mutations::DastScannerProfiles::Delete
        mount_mutation ::Mutations::DastSiteTokens::Create
        mount_mutation ::Mutations::QualityManagement::TestCases::Create
        mount_mutation ::Mutations::Analytics::KnowledgeGraph::OrbitUpdate, experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::Analytics::Orbit::StartTrial, experiment: { milestone: '19.5' }
        mount_mutation ::Mutations::Analytics::Orbit::ExcludedGroupCreate, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::Analytics::Orbit::ExcludedGroupDestroy, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::Analytics::Orbit::InstanceStartTrial, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::Analytics::DevopsAdoption::EnabledNamespaces::Enable
        mount_mutation ::Mutations::Analytics::DevopsAdoption::EnabledNamespaces::BulkEnable
        mount_mutation ::Mutations::Analytics::DevopsAdoption::EnabledNamespaces::Disable
        mount_mutation ::Mutations::Analytics::CustomDashboards::Create, experiment: { milestone: '18.7' }
        mount_mutation ::Mutations::Analytics::CustomDashboards::Update, experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::Analytics::CustomDashboards::Delete, experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::IncidentManagement::OncallSchedule::Create
        mount_mutation ::Mutations::IncidentManagement::OncallSchedule::Update
        mount_mutation ::Mutations::IncidentManagement::OncallSchedule::Destroy
        mount_mutation ::Mutations::IncidentManagement::OncallRotation::Create
        mount_mutation ::Mutations::IncidentManagement::OncallRotation::Update
        mount_mutation ::Mutations::IncidentManagement::OncallRotation::Destroy
        mount_mutation ::Mutations::IncidentManagement::EscalationPolicy::Create
        mount_mutation ::Mutations::IncidentManagement::EscalationPolicy::Update
        mount_mutation ::Mutations::IncidentManagement::EscalationPolicy::Destroy
        mount_mutation ::Mutations::IncidentManagement::IssuableResourceLink::Create
        mount_mutation ::Mutations::IncidentManagement::IssuableResourceLink::Destroy
        mount_mutation ::Mutations::AppSec::Fuzzing::Coverage::Corpus::Create
        mount_mutation ::Mutations::Projects::SetComplianceFramework,
          deprecated: { reason: 'Use mutation ProjectUpdateComplianceFrameworks instead of this', milestone: '17.11' }
        mount_mutation ::Mutations::Projects::ProjectSettingsUpdate, experiment: { milestone: '16.9' }
        mount_mutation ::Mutations::SecurityPolicy::CommitScanExecutionPolicy
        mount_mutation ::Mutations::SecurityPolicy::AssignSecurityPolicyProject
        mount_mutation ::Mutations::SecurityPolicy::UnassignSecurityPolicyProject
        mount_mutation ::Mutations::SecurityPolicy::CreateSecurityPolicyProject
        mount_mutation ::Mutations::SecurityPolicy::CreateSecurityPolicyProjectAsync, experiment: { milestone: '17.3' }
        mount_mutation ::Mutations::SecurityPolicy::ResyncSecurityPolicies, experiment: { milestone: '18.1' }
        mount_mutation ::Mutations::Security::CiConfiguration::ConfigureDependencyScanning
        mount_mutation ::Mutations::Security::CiConfiguration::ConfigureContainerScanning
        mount_mutation ::Mutations::Security::TrainingProviderUpdate
        mount_mutation ::Mutations::Security::ProjectSecurityExclusionCreate
        mount_mutation ::Mutations::Security::ProjectSecurityExclusionUpdate
        mount_mutation ::Mutations::Security::ProjectSecurityExclusionDelete
        mount_mutation ::Mutations::Security::Attributes::Create
        mount_mutation ::Mutations::Security::Attributes::Update
        mount_mutation ::Mutations::Security::Attributes::Destroy
        mount_mutation ::Mutations::Security::Attributes::ProjectUpdate
        mount_mutation ::Mutations::Security::Attributes::BulkUpdate
        mount_mutation ::Mutations::Security::Categories::Create
        mount_mutation ::Mutations::Security::Categories::Update
        mount_mutation ::Mutations::Security::Categories::Destroy
        mount_mutation ::Mutations::Security::ScanProfiles::Attach, experiment: { milestone: '18.9' },
          scopes: [:api, :ai_workflows]
        mount_mutation ::Mutations::Security::ScanProfiles::Detach, experiment: { milestone: '18.9' }
        mount_mutation ::Mutations::Security::ScanProfiles::Create, experiment: { milestone: '19.3' }
        mount_mutation ::Mutations::Security::ScanProfiles::Update, experiment: { milestone: '19.3' }
        mount_mutation ::Mutations::Security::ScanProfiles::Delete, experiment: { milestone: '19.3' }
        mount_mutation ::Mutations::Security::Ascp::ScanCreate, experiment: { milestone: '18.10' },
          scopes: [:api, :ai_workflows]
        mount_mutation ::Mutations::Security::Ascp::ComponentCreate, experiment: { milestone: '18.11' },
          scopes: [:api, :ai_workflows]
        mount_mutation ::Mutations::Security::Ascp::SecurityContextCreate, experiment: { milestone: '18.11' },
          scopes: [:api, :ai_workflows]
        mount_mutation ::Mutations::Security::PipelineExecutionSchedulePolicy::TestRun,
          experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::Users::Abuse::NamespaceBans::Destroy
        mount_mutation ::Mutations::Users::MemberRoles::Assign, experiment: { milestone: '17.7' }
        mount_mutation ::Mutations::AuditEvents::ExternalAuditEventDestinations::Create, deprecated: {
          reason: 'Use `groupAuditEventStreamingDestinationsCreate` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::ExternalAuditEventDestinations::Destroy, deprecated: {
          reason: 'Use `groupAuditEventStreamingDestinationsDelete` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::ExternalAuditEventDestinations::Update, deprecated: {
          reason: 'Use `groupAuditEventStreamingDestinationsUpdate` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::Ci::NamespaceCiCdSettingsUpdate
        mount_mutation ::Mutations::Ci::Runners::ExportUsage
        mount_mutation ::Mutations::RemoteDevelopment::WorkspaceOperations::Create
        mount_mutation ::Mutations::RemoteDevelopment::WorkspaceOperations::Update
        mount_mutation ::Mutations::RemoteDevelopment::DevfileOperations::Validate, experiment: { milestone: '18.4' }
        mount_mutation ::Mutations::RemoteDevelopment::NamespaceClusterAgentMappingOperations::Create
        mount_mutation ::Mutations::RemoteDevelopment::NamespaceClusterAgentMappingOperations::Delete
        mount_mutation ::Mutations::RemoteDevelopment::OrganizationClusterAgentMappingOperations::Create, experiment: {
          milestone: '17.11'
        }
        mount_mutation ::Mutations::RemoteDevelopment::OrganizationClusterAgentMappingOperations::Delete, experiment: {
          milestone: '17.11'
        }
        mount_mutation ::Mutations::AuditEvents::Streaming::Headers::Destroy, deprecated: {
          reason: 'Configure headers by using the streaming destination configuration. ' \
            'Use `groupAuditEventStreamingDestinationsUpdate`',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::Streaming::Headers::Create, deprecated: {
          reason: 'Configure headers by using the streaming destination configuration. ' \
            'Use `groupAuditEventStreamingDestinationsUpdate`',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::Streaming::Headers::Update, deprecated: {
          reason: 'Configure headers by using the streaming destination configuration. ' \
            'Use `groupAuditEventStreamingDestinationsUpdate`',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::Streaming::EventTypeFilters::Create, deprecated: {
          reason: 'Use `auditEventsGroupDestinationEventsAdd` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::Streaming::EventTypeFilters::Destroy, deprecated: {
          reason: 'Use `auditEventsGroupDestinationEventsRemove` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::Deployments::DeploymentApprove
        mount_mutation ::Mutations::MergeRequests::UpdateApprovalRule
        mount_mutation ::Mutations::MergeRequests::DestroyRequestedChanges
        mount_mutation ::Mutations::MergeRequests::DismissPolicyViolations, experiment: { milestone: '18.4' }
        mount_mutation ::Mutations::MergeRequests::BypassSecurityPolicy, experiment: { milestone: '18.5' }
        mount_mutation ::Mutations::MergeRequests::ResyncSecurityPolicies, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::MergeRequests::SetBlockingMergeRequests
        mount_mutation ::Mutations::Ai::Action, experiment: { milestone: '15.11' }, scopes: [:api, :ai_features]
        mount_mutation ::Mutations::Ai::DuoUserFeedback, experiment: {
          milestone: '16.10'
        }, scopes: [:api, :ai_features]
        mount_mutation ::Mutations::AuditEvents::InstanceExternalAuditEventDestinations::Create, deprecated: {
          reason: 'Use `instanceAuditEventStreamingDestinationsCreate` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::InstanceExternalAuditEventDestinations::Destroy, deprecated: {
          reason: 'Use `instanceAuditEventStreamingDestinationsDelete` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::InstanceExternalAuditEventDestinations::Update, deprecated: {
          reason: 'Use `instanceAuditEventStreamingDestinationsUpdate` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::GoogleCloudLoggingConfigurations::Create, deprecated: {
          reason: 'Use `groupAuditEventStreamingDestinationsCreate` with `gcpLogging` category instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::GoogleCloudLoggingConfigurations::Destroy, deprecated: {
          reason: 'Use `groupAuditEventStreamingDestinationsDelete` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::GoogleCloudLoggingConfigurations::Update, deprecated: {
          reason: 'Use `groupAuditEventStreamingDestinationsUpdate` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::AmazonS3Configurations::Create, deprecated: {
          reason: 'Use `groupAuditEventStreamingDestinationsCreate` with `amazonS3` category instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::AmazonS3Configurations::Delete, deprecated: {
          reason: 'Use `groupAuditEventStreamingDestinationsDelete` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::AmazonS3Configurations::Update, deprecated: {
          reason: 'Use `groupAuditEventStreamingDestinationsUpdate` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::Instance::AmazonS3Configurations::Create, deprecated: {
          reason: 'Use `instanceAuditEventStreamingDestinationsCreate` with `amazonS3` category instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::Instance::AmazonS3Configurations::Delete, deprecated: {
          reason: 'Use `instanceAuditEventStreamingDestinationsDelete` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::Instance::AmazonS3Configurations::Update, deprecated: {
          reason: 'Use `instanceAuditEventStreamingDestinationsUpdate` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::Instance::GoogleCloudLoggingConfigurations::Create, deprecated: {
          reason: 'Use `instanceAuditEventStreamingDestinationsCreate` with `gcpLogging` category instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::Streaming::InstanceHeaders::Create, deprecated: {
          reason: 'Configure headers by using the streaming destination configuration. ' \
            'Use `instanceAuditEventStreamingDestinationsUpdate`',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::Streaming::InstanceHeaders::Update, deprecated: {
          reason: 'Configure headers by using the streaming destination configuration. ' \
            'Use `instanceAuditEventStreamingDestinationsUpdate`',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::Streaming::InstanceHeaders::Destroy, deprecated: {
          reason: 'Configure headers by using the streaming destination configuration. ' \
            'Use `instanceAuditEventStreamingDestinationsUpdate`',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::Streaming::InstanceEventTypeFilters::Create, deprecated: {
          reason: 'Use `auditEventsInstanceDestinationEventsAdd` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::Streaming::InstanceEventTypeFilters::Destroy, deprecated: {
          reason: 'Use `auditEventsInstanceDestinationEventsRemove` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::Security::CiConfiguration::ProjectSetContinuousVulnerabilityScanning, deprecated: {
          milestone: '17.3',
          reason: 'CVS has been enabled permanently. See [this ' \
            'epic](https://gitlab.com/groups/gitlab-org/-/epics/11474) for more information'
        }
        mount_mutation ::Mutations::Security::CiConfiguration::SetSecretPushProtection
        mount_mutation ::Mutations::Security::CiConfiguration::SetPreReceiveSecretDetection
        mount_mutation ::Mutations::Security::CiConfiguration::SetGroupSecretPushProtection
        mount_mutation ::Mutations::Security::CiConfiguration::SetGroupValidityChecks
        mount_mutation ::Mutations::Security::CiConfiguration::SetValidityChecks
        mount_mutation ::Mutations::Security::CiConfiguration::SetContainerScanningForRegistry
        mount_mutation ::Mutations::Security::CiConfiguration::SetCvsForContainerScanning, experiment: { milestone: '19.0' }
        mount_mutation ::Mutations::Security::CiConfiguration::SetCvsForDependencyScanning, experiment: { milestone: '19.0' }
        mount_mutation ::Mutations::Security::CiConfiguration::SetLicenseConfigurationSource
        mount_mutation ::Mutations::Security::CiConfiguration::SetLicenseScanningForCyclonedx
        mount_mutation ::Mutations::AuditEvents::Instance::GoogleCloudLoggingConfigurations::Destroy, deprecated: {
          reason: 'Use `instanceAuditEventStreamingDestinationsDelete` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::Instance::GoogleCloudLoggingConfigurations::Update, deprecated: {
          reason: 'Use `instanceAuditEventStreamingDestinationsUpdate` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::DependencyProxy::Packages::Settings::Update
        mount_mutation ::Mutations::Analytics::CycleAnalytics::ValueStreams::Create, experiment: { milestone: '16.6' }
        mount_mutation ::Mutations::Analytics::CycleAnalytics::ValueStreams::Update, experiment: { milestone: '16.6' }
        mount_mutation ::Mutations::Analytics::CycleAnalytics::ValueStreams::Destroy, experiment: { milestone: '16.6' }
        mount_mutation ::Mutations::AuditEvents::Streaming::HTTP::NamespaceFilters::Create, deprecated: {
          reason: 'Use `auditEventsGroupDestinationNamespaceFilterCreate` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::AuditEvents::Streaming::HTTP::NamespaceFilters::Delete, deprecated: {
          reason: 'Use `auditEventsGroupDestinationNamespaceFilterDelete` instead',
          milestone: '18.10'
        }
        mount_mutation ::Mutations::ComplianceManagement::Standards::RefreshAdherenceChecks
        mount_mutation ::Mutations::Groups::SavedReplies::Create, experiment: { milestone: '16.10' }
        mount_mutation ::Mutations::Groups::SavedReplies::Update, experiment: { milestone: '16.10' }
        mount_mutation ::Mutations::Groups::SavedReplies::Destroy, experiment: { milestone: '16.10' }
        mount_mutation ::Mutations::Members::Groups::Export, experiment: { milestone: '17.4' }
        mount_mutation ::Mutations::Projects::SavedReplies::Create, experiment: { milestone: '16.11' }
        mount_mutation ::Mutations::Projects::SavedReplies::Update, experiment: { milestone: '16.11' }
        mount_mutation ::Mutations::Projects::SavedReplies::Destroy, experiment: { milestone: '16.11' }
        mount_mutation ::Mutations::BranchRules::ApprovalProjectRules::Create, experiment: { milestone: '16.10' }
        mount_mutation ::Mutations::ApprovalProjectRules::Update, experiment: { milestone: '16.10' }
        mount_mutation ::Mutations::ApprovalProjectRules::Delete, experiment: { milestone: '16.10' }
        mount_mutation ::Mutations::AuditEvents::Group::AuditEventStreamingDestinations::Create,
          experiment: { milestone: '16.11' }
        mount_mutation ::Mutations::AuditEvents::Group::AuditEventStreamingDestinations::Delete,
          experiment: { milestone: '16.11' }
        mount_mutation ::Mutations::AuditEvents::Group::AuditEventStreamingDestinations::Update,
          experiment: { milestone: '16.11' }
        mount_mutation ::Mutations::AuditEvents::Instance::AuditEventStreamingDestinations::Create,
          experiment: { milestone: '16.11' }
        mount_mutation ::Mutations::AuditEvents::Instance::AuditEventStreamingDestinations::Delete,
          experiment: { milestone: '16.11' }
        mount_mutation ::Mutations::AuditEvents::Instance::AuditEventStreamingDestinations::Update,
          experiment: { milestone: '16.11' }
        mount_mutation ::Mutations::AuditEvents::Group::EventTypeFilters::Create,
          experiment: { milestone: '17.0' }
        mount_mutation ::Mutations::AuditEvents::Group::EventTypeFilters::Delete,
          experiment: { milestone: '17.0' }
        mount_mutation ::Mutations::AuditEvents::Group::EventTypeFilters::DenylistCreate,
          experiment: { milestone: '19.1' }
        mount_mutation ::Mutations::AuditEvents::Group::EventTypeFilters::DenylistDelete,
          experiment: { milestone: '19.1' }
        mount_mutation ::Mutations::AuditEvents::Instance::EventTypeFilters::Create,
          experiment: { milestone: '17.0' }
        mount_mutation ::Mutations::AuditEvents::Instance::EventTypeFilters::Delete,
          experiment: { milestone: '17.0' }
        mount_mutation ::Mutations::AuditEvents::Instance::EventTypeFilters::DenylistCreate,
          experiment: { milestone: '19.6' }
        mount_mutation ::Mutations::AuditEvents::Instance::EventTypeFilters::DenylistDelete,
          experiment: { milestone: '19.6' }
        mount_mutation ::Mutations::AuditEvents::Group::NamespaceFilters::Create,
          experiment: { milestone: '17.0' }
        mount_mutation ::Mutations::AuditEvents::Group::NamespaceFilters::Delete,
          experiment: { milestone: '17.0' }
        mount_mutation ::Mutations::Ai::SelfHostedModels::Create,
          experiment: { milestone: '17.1' }
        mount_mutation ::Mutations::AuditEvents::Instance::NamespaceFilters::Create,
          experiment: { milestone: '17.2' }
        mount_mutation ::Mutations::AuditEvents::Instance::NamespaceFilters::Delete,
          experiment: { milestone: '17.2' }
        mount_mutation ::Mutations::Ai::SelfHostedModels::Update,
          experiment: { milestone: '17.2' }
        mount_mutation ::Mutations::Ai::SelfHostedModels::Delete,
          experiment: { milestone: '17.2' }
        mount_mutation ::Mutations::MergeTrains::Cars::Delete, experiment: { milestone: '17.2' }
        mount_mutation ::Mutations::Projects::UpdateComplianceFrameworks
        mount_mutation ::Mutations::Ai::FeatureSettings::Update, experiment: { milestone: '17.4' }
        mount_mutation ::Mutations::Ai::FeatureSettings::ModelAllowlistUpdate, experiment: { milestone: '19.1' }
        mount_mutation ::Mutations::Projects::TargetBranchRules::Create
        mount_mutation ::Mutations::Projects::TargetBranchRules::Destroy
        mount_mutation ::Mutations::ComplianceManagement::ComplianceFramework::ComplianceRequirements::Create,
          experiment: { milestone: '17.6' }
        mount_mutation ::Mutations::ComplianceManagement::ComplianceFramework::ComplianceRequirements::Destroy,
          experiment: { milestone: '17.7' }
        mount_mutation ::Mutations::ComplianceManagement::ComplianceFramework::ComplianceRequirements::Update,
          experiment: { milestone: '17.7' }
        mount_mutation ::Mutations::Ai::SelfHostedModels::ConnectionCheck,
          experiment: { milestone: '17.7' }
        mount_mutation ::Mutations::ComplianceManagement::ComplianceFramework::ComplianceRequirementsControls::Create,
          experiment: { milestone: '17.9' }
        mount_mutation ::Mutations::ComplianceManagement::ComplianceFramework::ComplianceRequirementsControls::Update,
          experiment: { milestone: '17.9' }
        mount_mutation ::Mutations::ComplianceManagement::ComplianceFramework::ComplianceRequirementsControls::Destroy,
          experiment: { milestone: '17.9' }
        mount_mutation ::Mutations::Ai::DuoSettings::Update, experiment: { milestone: '17.9' }
        mount_mutation ::Mutations::Ai::DeleteConversationThread, experiment: { milestone: '17.9' }
        mount_mutation ::Mutations::Ai::DuoWorkflows::DeleteWorkflow, experiment: { milestone: '18.1' }
        mount_mutation ::Mutations::Ai::DuoWorkflows::Create, experiment: { milestone: '18.1' },
          scopes: [:api, :ai_features]
        mount_mutation ::Mutations::Ai::DuoWorkflows::UpdateToolCallApprovals, experiment: { milestone: '18.9' },
          scopes: [:api, :ai_features]
        mount_mutation ::Mutations::Ai::DuoWorkflows::UpdateAgentPrivileges, experiment: { milestone: '19.2' },
          scopes: [:api, :ai_features]
        mount_mutation ::Mutations::Ai::DuoWorkflows::UpdateWebSearch, experiment: { milestone: '19.3' },
          scopes: [:api, :ai_features]
        mount_mutation ::Mutations::Ai::FunctionalVerificationCheck::CreateFunctionalVerificationWorkflow,
          experiment: { milestone: '19.5' }, scopes: [:api, :ai_features]
        mount_mutation ::Mutations::ArtifactRegistry::Role::Grant, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::ArtifactRegistry::Role::BulkGrant, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::ArtifactRegistry::Role::Revoke, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::ArtifactRegistry::Role::BulkRevoke, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::ArtifactRegistry::Repositories::Create, experiment: { milestone: '19.3' }
        mount_mutation ::Mutations::ArtifactRegistry::Repositories::Update, experiment: { milestone: '19.3' }
        mount_mutation ::Mutations::ArtifactRegistry::Repositories::Delete, experiment: { milestone: '19.3' }
        mount_mutation ::Mutations::ArtifactRegistry::Repositories::TestConnection, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::ArtifactRegistry::UpstreamTestConnection, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::ArtifactRegistry::Repositories::DeleteArtifacts, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::ArtifactRegistry::Artifacts::Delete, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::ArtifactRegistry::Versions::Delete, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::ArtifactRegistry::Versions::BulkDelete, experiment: { milestone: '19.6' }
        mount_mutation ::Mutations::ArtifactRegistry::Activate, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::ArtifactRegistry::Disable, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::ArtifactRegistry::Enable, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::ArtifactRegistry::Manifests::Delete, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::ArtifactRegistry::Manifests::BulkDelete, experiment: { milestone: '19.6' }
        mount_mutation ::Mutations::ArtifactRegistry::ContainerTags::Delete, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::ArtifactRegistry::NpmDistTags::Delete, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::ArtifactRegistry::UpstreamRepositories::Dissociate,
          experiment: { milestone: '19.5' }
        mount_mutation ::Mutations::Authz::LdapAdminRoleLinks::Create, experiment: { milestone: '17.11' }
        mount_mutation ::Mutations::Authz::LdapAdminRoleLinks::Destroy, experiment: { milestone: '18.0' }
        mount_mutation ::Mutations::Authz::AdminRoles::LdapSync, experiment: { milestone: '18.0' }
        mount_mutation ::Mutations::Ai::ModelSelection::Namespaces::Update, experiment: { milestone: '18.1' }
        mount_mutation ::Mutations::Ai::ModelSelection::Namespaces::ModelAllowlistUpdate,
          experiment: { milestone: '19.1' }
        mount_mutation ::Mutations::WorkItems::Lifecycles::Update, experiment: { milestone: '18.1' }
        mount_mutation ::Mutations::WorkItems::Lifecycles::Create, experiment: { milestone: '18.4' }
        mount_mutation ::Mutations::WorkItems::Lifecycles::AttachWorkItemType, experiment: { milestone: '18.4' }
        mount_mutation ::Mutations::WorkItems::Lifecycles::Delete, experiment: { milestone: '18.4' }
        mount_mutation ::Mutations::VirtualRegistries::Container::Upstream::Create,
          experiment: { milestone: '18.8' }
        mount_mutation ::Mutations::VirtualRegistries::Container::Registry::Destroy, experiment: { milestone: '18.9' }
        mount_mutation ::Mutations::VirtualRegistries::Container::Registry::Create, experiment: { milestone: '18.9' }
        mount_mutation ::Mutations::VirtualRegistries::Container::Registry::Update, experiment: { milestone: '18.9' }
        mount_mutation ::Mutations::VirtualRegistries::Container::Upstream::Destroy,
          experiment: { milestone: '18.9' }
        mount_mutation ::Mutations::VirtualRegistries::Container::Registry::Cache::Destroy,
          experiment: { milestone: '18.9' }
        mount_mutation ::Mutations::VirtualRegistries::Container::Upstream::Cache::Destroy,
          experiment: { milestone: '18.9' }
        mount_mutation ::Mutations::VirtualRegistries::Container::Cache::Entry::Destroy,
          experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::VirtualRegistries::Packages::Maven::Upstream::Create,
          experiment: { milestone: '18.2' }
        mount_mutation ::Mutations::VirtualRegistries::Packages::Maven::Upstream::Update,
          experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::VirtualRegistries::Packages::Maven::Registry::Destroy,
          experiment: { milestone: '18.9' }
        mount_mutation ::Mutations::VirtualRegistries::Packages::Maven::Registry::Create,
          experiment: { milestone: '18.9' }
        mount_mutation ::Mutations::VirtualRegistries::Packages::Maven::Upstream::Destroy,
          experiment: { milestone: '18.9' }
        mount_mutation ::Mutations::VirtualRegistries::Packages::Maven::Registry::Update,
          experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::VirtualRegistries::Packages::Maven::Registry::Cache::Destroy,
          experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::VirtualRegistries::Packages::Maven::Upstream::Cache::Destroy,
          experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::VirtualRegistries::Packages::Maven::Cache::Entry::Destroy,
          experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::ComplianceManagement::Projects::ComplianceViolations::Update
        mount_mutation ::Mutations::ComplianceManagement::Projects::ComplianceViolations::LinkIssue
        mount_mutation ::Mutations::ComplianceManagement::Projects::ComplianceViolations::UnlinkIssue
        mount_mutation ::Mutations::VirtualRegistries::Setting::Update, experiment: { milestone: '18.5' }
        mount_mutation ::Mutations::VirtualRegistries::Cleanup::Policy::Upsert, experiment: { milestone: '18.7' }
        mount_mutation ::Mutations::VirtualRegistries::Container::Upstream::Update,
          experiment: { milestone: '18.8' }
        mount_mutation ::Mutations::WorkItems::Types::Create, experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::WorkItems::Types::Update, experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::WorkItems::Types::AvailabilityToggle, experiment: { milestone: '18.11' }
        mount_mutation ::Mutations::WorkItems::Settings::Update, experiment: { milestone: '19.0' }
        mount_mutation ::Mutations::WorkItems::EnableAiPlanning, experiment: { milestone: '19.3' }
        mount_mutation ::Mutations::WorkItems::GenerateWorkplan, experiment: { milestone: '19.3' }
        mount_mutation ::Mutations::WorkItems::GenerateReadinessScore, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::WorkItems::ResumeWorkplan, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::WorkItems::ResolveWorkplanQuestions, experiment: { milestone: '19.6' }
        mount_mutation ::Mutations::WorkItems::Decisions::Create, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::WorkItems::Decisions::Resolve, experiment: { milestone: '19.4' }
        mount_mutation ::Mutations::WorkItems::Decisions::Update, experiment: { milestone: '19.5' }
        mount_mutation ::Mutations::WorkItems::Decisions::Archive, experiment: { milestone: '19.5' }
        mount_mutation ::Mutations::WorkItems::Decisions::Delete, experiment: { milestone: '19.5' }
        mount_mutation ::Mutations::VirtualRegistries::Container::Registry::Upstream::Create,
          experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::VirtualRegistries::Container::Registry::Upstream::Destroy,
          experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::VirtualRegistries::Container::Upstream::Test,
          experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::VirtualRegistries::Container::RegistryUpstream::Update,
          experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::VirtualRegistries::Packages::Maven::RegistryUpstream::Update,
          experiment: { milestone: '18.10' }
        mount_mutation ::Mutations::VirtualRegistries::Packages::Maven::Registry::Upstream::Destroy,
          experiment: { milestone: '18.11' }
        mount_mutation ::Mutations::Ai::DomainSettings::InstanceUpdate, experiment: { milestone: '19.0' }
        mount_mutation ::Mutations::Ai::DomainSettings::NamespaceUpdate, experiment: { milestone: '19.0' }
        mount_mutation ::Mutations::Ai::DuoSettings::SetDuoAvailability, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::Ai::DuoSettings::ClearDuoAvailability, experiment: { milestone: '19.2' }
        mount_mutation ::Mutations::Vulnerabilities::StartVulnerabilityWorkflow,
          scopes: [:api, :ai_workflows]
        mount_mutation ::Mutations::Vulnerabilities::CancelVulnerabilityWorkflow,
          scopes: [:api, :ai_workflows]

        prepend(Types::DeprecatedMutations)
      end
    end
  end
end
