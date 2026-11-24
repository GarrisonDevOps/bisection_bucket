# frozen_string_literal: true

module Gitlab
  module EventStore
    module Subscriptions
      class SecuritySubscriptions < BaseSubscriptions
        def register
          store.subscribe ::Security::RefreshProjectPoliciesWorker,
            to: ::ProjectAuthorizations::AuthorizationsChangedEvent,
            delay: 1.minute
          store.subscribe ::Security::ScanResultPolicies::AddApproversToRulesWorker,
            to: ::ProjectAuthorizations::AuthorizationsAddedEvent,
            if: ->(event) { ::Security::ScanResultPolicies::AddApproversToRulesWorker.dispatch?(event) }
          store.subscribe ::Security::Scans::PurgeByJobIdWorker, to: ::Ci::JobArtifactsDeletedEvent
          store.subscribe ::Security::Scans::IngestReportsWorker, to: ::Ci::JobSecurityScanCompletedEvent

          register_dependency_firewall_subscribers
          register_security_policy_subscribers
          register_security_insights_subscribers
          register_security_project_tracked_context_subscribers
        end

        private

        def register_dependency_firewall_subscribers
          [
            ::Projects::ProjectTransferedEvent,
            ::Projects::ProjectDeletedEvent,
            ::Groups::GroupTransferedEvent,
            ::Groups::GroupDeletedEvent
          ].each do |event_class|
            store.subscribe ::Security::DependencyFirewall::ScheduleGroupPreventedStatsRefreshWorker,
              to: event_class,
              if: ->(event) { ::Security::DependencyFirewall::ScheduleGroupPreventedStatsRefreshWorker.dispatch?(event) }
          end
        end

        def register_security_policy_subscribers
          store.subscribe ::Security::SyncPolicyConfigurationWorker,
            to: ::Security::PolicyConfigurationAssignedEvent
          store.subscribe ::Security::SyncPolicyConfigurationWorker,
            to: ::Security::PolicyConfigurationResyncEvent

          store.subscribe ::Security::SyncPolicyWorker, to: ::Security::PolicyCreatedEvent
          store.subscribe ::Security::SyncPolicyWorker, to: ::Security::PolicyDeletedEvent
          store.subscribe ::Security::SyncPolicyWorker, to: ::Security::PolicyUpdatedEvent
          store.subscribe ::Security::SyncPolicyWorker, to: ::Security::PolicyResyncEvent

          store.subscribe ::Security::ScanResultPolicies::AuditWarnModeGroupProtectedBranchesOverridesWorker,
            to: ::Security::PolicyCreatedEvent
          store.subscribe ::Security::ScanResultPolicies::AuditWarnModeGroupProtectedBranchesOverridesWorker,
            to: ::Security::PolicyUpdatedEvent

          store.subscribe ::Security::ScanResultPolicies::CreateWarnModeApprovalAuditEventsWorker,
            to: ::MergeRequests::ApprovedEvent,
            if: ->(event) { ::Security::ScanResultPolicies::CreateWarnModeApprovalAuditEventsWorker.dispatch?(event) }

          protected_branch_events = [
            ::Repositories::ProtectedBranchCreatedEvent, ::Repositories::ProtectedBranchDestroyedEvent
          ]
          store.subscribe ::Security::SyncPolicyEventWorker, to: protected_branch_events,
            if: ->(event) { !::Security::SyncPolicyEventWorker.debounce?(event) }
          store.subscribe ::Security::SyncPolicyEventWorker, to: protected_branch_events,
            if: ->(event) { ::Security::SyncPolicyEventWorker.debounce?(event) },
            delay: ::Security::SyncPolicyEventWorker::DEBOUNCE_DELAY
          store.subscribe ::Security::SyncPolicyEventWorker, to: ::Repositories::DefaultBranchChangedEvent
          store.subscribe ::Security::SyncPolicyEventWorker, to: ::Projects::ComplianceFrameworkChangedEvent
          store.subscribe ::Security::SyncPolicyEventWorker, to: ::Projects::SecurityAttributeChangedEvent

          store.subscribe ::Security::ScanResultPolicies::CleanupMergeRequestViolationsWorker,
            to: ::MergeRequests::ClosedEvent
          store.subscribe ::Security::ScanResultPolicies::CleanupMergeRequestViolationsWorker,
            to: ::MergeRequests::MergedEvent

          store.subscribe ::Security::ScanResultPolicies::ProcessPipelineCompletionWorker,
            to: ::Ci::PipelineFinishedEvent
          store.subscribe ::Security::ScanResultPolicies::ProcessPipelineCompletionWorker,
            to: ::Security::ReportsIngestedEvent

          store.subscribe ::Security::PipelineExecutionSchedulePolicies::TestRunCompletionWorker,
            to: ::Ci::PipelineFinishedEvent,
            if: ->(event) {
              ::Security::ScheduledPipelineExecutionPolicyTestRun.for_pipeline_id(event.data[:pipeline_id]).exists?
            }

          store.subscribe ::Security::Policies::DismissalPreserveWorker, to: ::Security::PolicyDismissalPreservedEvent
        end

        def register_security_insights_subscribers
          store.subscribe ::Security::ProcessTrackedContextProjectTransferEventsWorker,
            to: ::Projects::ProjectTransferedEvent
          store.subscribe ::Security::ProcessTrackedContextGroupTransferEventsWorker,
            to: ::Groups::GroupTransferedEvent

          store.subscribe ::Security::AnalyzersStatus::ProcessArchivedEventsWorker, to: ::Projects::ProjectArchivedEvent
          store.subscribe ::Security::AnalyzersStatus::ProcessDeletedEventsWorker, to: ::Projects::ProjectDeletedEvent
          store.subscribe ::Security::AnalyzersStatus::ProcessGroupTransferEventsWorker,
            to: ::Groups::GroupTransferedEvent
          store.subscribe ::Security::AnalyzersStatus::ProcessProjectTransferEventsWorker,
            to: ::Projects::ProjectTransferedEvent
          store.subscribe ::Security::AnalyzersStatus::ProcessGroupArchivedEventsWorker,
            to: ::Namespaces::Groups::GroupArchivedEvent
          store.subscribe ::Security::AnalyzersStatus::IngestionSubscriberWorker,
            to: ::Security::ReportsIngestedEvent

          store.subscribe ::Security::AnalyzerNamespaceStatuses::ProcessGroupDeletedEventsWorker,
            to: ::Groups::GroupDeletedEvent

          store.subscribe ::Security::Attributes::ProcessProjectTransferEventsWorker,
            to: ::Projects::ProjectTransferedEvent
          store.subscribe ::Security::Attributes::CleanupScheduleWorker,
            to: ::Groups::GroupTransferedEvent

          store.subscribe ::Security::ScanProfiles::ProcessProjectTransferEventsWorker,
            to: ::Projects::ProjectTransferedEvent
          store.subscribe ::Security::ScanProfiles::ProcessGroupTransferEventsWorker,
            to: ::Groups::GroupTransferedEvent
          store.subscribe ::Security::ScanProfiles::ProcessArchivedEventsWorker,
            to: ::Projects::ProjectArchivedEvent
          store.subscribe ::Security::ScanProfiles::ProcessArchivedEventsWorker,
            to: ::Namespaces::Groups::GroupArchivedEvent
        end

        def register_security_project_tracked_context_subscribers
          store.subscribe ::Security::ProjectTrackedContexts::CreateOrUpdateDefaultTrackedContextWorker,
            to: ::Projects::ProjectCreatedEvent
          store.subscribe ::Security::ProjectTrackedContexts::CreateOrUpdateDefaultTrackedContextWorker,
            to: ::Repositories::DefaultBranchChangedEvent,
            if: ->(event) { event.data[:container_type] == 'Project' }
          store.subscribe ::Security::ProjectTrackedContexts::CreateOrUpdateDefaultTrackedContextWorker,
            to: ::Repositories::RepositoryCreatedEvent,
            if: ->(event) { event.data[:container_type] == 'Project' }
          store.subscribe ::Security::ProjectTrackedContexts::ReindexVulnerabilitiesOnDefaultBranchChangeWorker,
            to: ::Repositories::DefaultBranchChangedEvent,
            if: ->(event) {
              event.data[:container_type] == 'Project' &&
                ::Search::Elastic::VulnerabilityIndexHelper.indexing_allowed? &&
                ::Elastic::DataMigrationService.migration_has_finished?(:add_is_default_to_vulnerability) &&
                ::Security::ProjectTrackedContexts::ReindexVulnerabilitiesOnDefaultBranchChangeWorker.dispatch?(event)
            }
          store.subscribe ::Security::ProjectTrackedContexts::ReindexSbomOccurrencesOnDefaultBranchChangeWorker,
            to: ::Repositories::DefaultBranchChangedEvent,
            if: ->(event) {
              event.data[:container_type] == 'Project' &&
                ::Search::Elastic::SbomOccurrenceRefIndexHelper.indexing_allowed? &&
                ::Security::ProjectTrackedContexts::ReindexSbomOccurrencesOnDefaultBranchChangeWorker.dispatch?(event)
            }
        end
      end
    end
  end
end
