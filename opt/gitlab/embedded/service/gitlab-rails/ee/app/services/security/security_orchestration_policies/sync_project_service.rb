# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class SyncProjectService < BaseProjectPolicyService
      def initialize(security_policy:, project:, policy_changes:, defer_policy_mr_sync: false)
        super(security_policy: security_policy, project: project)
        @policy_changes = policy_changes
        @defer_policy_mr_sync = defer_policy_mr_sync
      end

      def execute
        if policy_diff.any_changes?
          # Existing policy has been changed.
          sync_policy_changes
        else
          # Policy has just been created, link it.
          link_policy(defer_policy_mr_sync: defer_policy_mr_sync)
        end

        schedule_warn_mode_audit_events_worker
      end

      private

      attr_reader :policy_changes, :defer_policy_mr_sync

      def policy_diff
        Security::SecurityOrchestrationPolicies::PolicyDiff::Diff.from_json(
          policy_changes[:diff], policy_changes[:rules_diff]
        )
      end
      strong_memoize_attr :policy_diff

      def sync_policy_changes
        return unlink_policy if should_unlink_policy?
        return link_policy if should_link_policy?
        return if policy_disabled_or_scope_inapplicable?

        if security_policy.type_approval_policy?
          sync_approval_policy_diff(policy_diff)
          sync_project_finding_enrichments
          track_branch_exceptions_bypass_settings
          # Branches/branch_type only live on rule content, so skip the Gitaly-touching check
          # when this sync didn't touch any rule (e.g. an approvers-only edit).
          track_target_branch_not_protected if policy_diff.rules_diff.any_changes?
        elsif security_policy.type_pipeline_execution_schedule_policy?
          cancel_policy_pipelines_for_project if policy_diff.schedule_snoozed?
          recreate_pipeline_execution_schedule_project_schedules(project, security_policy)
        elsif security_policy.type_scan_execution_policy?
          recreate_scan_execution_project_schedules(project, security_policy)
        end
      end

      def should_unlink_policy?
        return false unless policy_status_changed_and_disabled? || policy_scope_changed_and_unscoped?

        # Scope and status changes fan out to every project of the configuration, so skip the
        # costly cleanup for projects that never had the policy.
        unlink_policy_needed?
      end

      def should_link_policy?
        policy_status_changed_and_enabled? || policy_scope_changed_and_scoped? || policy_not_linked_to_project?
      end

      def policy_status_changed_and_enabled?
        policy_diff.status_changed? && security_policy.enabled?
      end

      def policy_status_changed_and_disabled?
        policy_diff.status_changed? && !security_policy.enabled?
      end

      def policy_scope_changed_and_scoped?
        policy_diff.scope_changed? && scope_applicable?
      end

      def policy_not_linked_to_project?
        scope_applicable? && !security_policy.linked_to_project?(project)
      end

      def policy_scope_changed_and_unscoped?
        policy_diff.scope_changed? && !scope_applicable?
      end

      def schedule_warn_mode_audit_events_worker
        return unless security_policy.type_approval_policy? && security_policy.warn_mode?
        return if policy_disabled_or_scope_inapplicable?

        Security::ScanResultPolicies::CreateProjectWarnModePushSettingsAuditEventsWorker
          .perform_async(project.id, security_policy.id)
      end
    end
  end
end
