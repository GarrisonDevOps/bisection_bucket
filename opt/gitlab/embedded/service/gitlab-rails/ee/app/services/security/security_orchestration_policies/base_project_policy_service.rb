# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class BaseProjectPolicyService
      include Gitlab::Utils::StrongMemoize
      include Gitlab::InternalEventsTracking
      include ::Security::ScanResultPolicies::PolicyViolationCommentGenerator

      def initialize(project:, security_policy:)
        @project = project
        @security_policy = security_policy
      end

      private

      attr_reader :project, :security_policy

      def link_policy(defer_policy_mr_sync: false)
        return if policy_disabled_or_scope_inapplicable?

        security_policy.transaction do
          security_policy.link_project!(project)

          if security_policy.type_pipeline_execution_schedule_policy?
            recreate_pipeline_execution_schedule_project_schedules(project, security_policy)
          elsif security_policy.type_scan_execution_policy?
            recreate_scan_execution_project_schedules(project, security_policy)
          end
        end

        return unless security_policy.type_approval_policy?

        # A reordered sibling policy may still hold this policy's index in its reads
        realign_policy_indexes
        create_approval_policy_rules

        unless defer_policy_mr_sync
          sync_merge_request_rules
          sync_project_finding_enrichments
        end

        track_branch_exceptions_bypass_settings
        track_target_branch_not_protected
      end

      def unlink_policy(skip_delete_worker: false, defer_policy_mr_sync: false)
        security_policy.unlink_project!(project)

        if security_policy.type_approval_policy?
          delete_approval_policy_rules(security_policy.approval_policy_rules)
          enqueue_policy_violation_comment_updates unless skip_delete_worker

          sync_merge_request_rules unless defer_policy_mr_sync

          unless skip_delete_worker
            rules = security_policy.approval_policy_rules
            return if Security::ApprovalPolicyRuleProjectLink.for_policy_rules(rules.select(:id)).exists?

            Security::DeleteApprovalPolicyRulesWorker.perform_in(1.minute, rules.map(&:id))
          end
        end

        if security_policy.type_pipeline_execution_schedule_policy?
          cancel_policy_pipelines_for_project
          security_policy
            .security_pipeline_execution_project_schedules
            .for_project(project)
            .delete_all
        elsif security_policy.type_scan_execution_policy?
          delete_scan_execution_project_schedules(project, security_policy)
        end
      end

      def sync_approval_policy_rules(approval_policy_rules = security_policy.approval_policy_rules.undeleted)
        update_approval_policy_rules(approval_policy_rules)
        sync_merge_request_rules
      end

      def sync_approval_policy_diff(policy_diff)
        realign_policy_indexes if policy_diff.policy_index_changed?
        created_rules, deleted_rules = find_changed_rules(policy_diff)
        security_policy.update_project_approval_policy_rule_links(project, created_rules, deleted_rules)

        if policy_diff.needs_complete_rules_refresh?
          rules = security_policy.approval_policy_rules.undeleted
          delete_approval_policy_rules(rules)
          create_approval_policy_rules(rules)
        else
          delete_approval_policy_rules(deleted_rules)
          create_approval_policy_rules(created_rules)

          if policy_diff.needs_rules_refresh?
            update_approval_policy_rules(security_policy.approval_policy_rules.undeleted)
          end
        end

        sync_merge_request_rules
      end

      def scope_applicable?
        security_policy.scope_applicable?(project)
      end

      # Approval rules and reads only exist for linked projects. Leftovers (an interrupted unlink already
      # deleted the link, and maybe some rules) still need the cleanup on retry.
      def unlink_policy_needed?
        !security_policy.type_approval_policy? ||
          security_policy.linked_to_project?(project) ||
          approval_rules_remain_in_project?
      end

      def approval_rules_remain_in_project?
        rules = security_policy.approval_policy_rules

        project.approval_rules.for_approval_policy_rules(rules).exists? ||
          project.scan_result_policy_reads.for_approval_policy_rules(rules).exists? ||
          ApprovalMergeRequestRule.for_unmerged_merge_requests.for_merge_request_project(project.id)
            .for_approval_policy_rules(rules).exists?
      end

      def policy_disabled_or_scope_inapplicable?
        !security_policy.enabled || !scope_applicable?
      end

      def recreate_pipeline_execution_schedule_project_schedules(project, security_policy)
        Security::SecurityOrchestrationPolicies::PipelineExecutionPolicies::CreateProjectSchedulesService
          .new(project: project, security_policy: security_policy)
          .execute
      end

      def recreate_scan_execution_project_schedules(project, security_policy)
        Security::SecurityOrchestrationPolicies::ScanExecutionPolicies::CreateProjectSchedulesService
          .new(project: project, security_policy: security_policy)
          .execute
      end

      def delete_scan_execution_project_schedules(project, security_policy)
        security_policy
          .scan_execution_project_schedules
          .for_project(project)
          .delete_all
      end

      def cancel_policy_pipelines_for_project
        Security::PipelineExecutionPolicies::CancelPolicyPipelinesWorker.perform_async(
          security_policy.id,
          project.id
        )
      end

      def track_branch_exceptions_bypass_settings
        return unless security_policy.bypass_settings.branches.any?

        track_internal_event('check_branch_exceptions_bypass_settings_for_approval_policy', project: project)
      end

      # A policy rule that resolves to no protected branches in this project never applies to
      # any merge request here (rules only enforce against protected target branches), so it
      # silently never enforces even though it shows as "Enabled". One `PolicyBranchesService`
      # instance is reused across rules so the branch list and protected-branch query are each
      # fetched once per sync, not once per rule.
      def track_target_branch_not_protected
        policy_branches_service = Security::SecurityOrchestrationPolicies::PolicyBranchesService.new(project: project)

        # An empty result only means "unenforceable" for rules that resolve to all protected
        # branches (`branches: []`, or `branch_type: protected` with no exceptions) - other rules
        # fall back to applying to every protected branch when they match none explicitly (see
        # ApprovalProjectRule#applies_to_branch?), so they're not actually dead.
        has_unenforceable_rule = security_policy.approval_policy_rules.undeleted.any? do |rule|
          rule.rule.applies_to_all_protected_branches? &&
            policy_branches_service.protected_branches_for(rule.content.deep_symbolize_keys).empty?
        end

        return unless has_unenforceable_rule

        track_internal_event('check_target_branch_not_protected_for_approval_policy', project: project)
      end

      def sync_merge_request_rules
        Security::SecurityOrchestrationPolicies::SyncMergeRequestsService.new(
          project: project, security_policy: security_policy
        ).execute
      end

      def enqueue_policy_violation_comment_updates
        merge_requests = project.merge_requests.opened
        # When this policy disables the bot message, only update MRs that already
        # have a policy bot comment (to refresh/clear it). MRs without an existing
        # comment have nothing to do.
        if security_policy.approval_policy.bot_message_disabled?
          merge_requests = merge_requests.with_policy_bot_comment(project)
        end

        merge_requests.each_batch do |batch|
          Security::GeneratePolicyViolationCommentWorker.bulk_perform_async_with_contexts(
            batch,
            arguments_proc: ->(merge_request) { merge_request.id },
            context_proc: ->(_) { { project: project } }
          )
        end
      end

      def sync_project_finding_enrichments
        return unless security_policy.has_enrichment_filters?

        Security::ScanResultPolicies::SyncProjectFindingEnrichmentsWorker
          .perform_async(project.id, security_policy.id)
      end

      def delete_approval_policy_rules(approval_policy_rules = security_policy.approval_policy_rules)
        Security::ScanResultPolicies::ApprovalRules::DeleteService.new(
          project: project,
          security_policy: security_policy,
          approval_policy_rules: approval_policy_rules
        ).execute
      end

      def update_approval_policy_rules(approval_policy_rules = security_policy.approval_policy_rules.undeleted)
        Security::ScanResultPolicies::ApprovalRules::UpdateService.new(
          project: project,
          security_policy: security_policy,
          approval_policy_rules: approval_policy_rules,
          author: approval_policy_author
        ).execute
      end

      def create_approval_policy_rules(approval_policy_rules = security_policy.approval_policy_rules.undeleted)
        Security::ScanResultPolicies::ApprovalRules::CreateService.new(
          project: project,
          security_policy: security_policy,
          approval_policy_rules: approval_policy_rules,
          author: approval_policy_author
        ).execute
      end

      def find_changed_rules(policy_diff)
        created_rules = find_policy_rules(policy_diff.rules_diff.created.map(&:id))
        deleted_rules = find_policy_rules(policy_diff.rules_diff.deleted.map(&:id))

        [created_rules, deleted_rules]
      end

      def find_policy_rules(policy_rule_ids)
        security_policy.approval_policy_rules.id_in(policy_rule_ids)
      end

      def realign_policy_indexes
        Security::ScanResultPolicies::RealignPolicyIndexesService.new(
          project: project,
          policy_configuration: security_policy.security_orchestration_policy_configuration
        ).execute
      end

      def approval_policy_author
        security_policy.security_orchestration_policy_configuration.policy_last_updated_by
      end
      strong_memoize_attr :approval_policy_author
    end
  end
end
