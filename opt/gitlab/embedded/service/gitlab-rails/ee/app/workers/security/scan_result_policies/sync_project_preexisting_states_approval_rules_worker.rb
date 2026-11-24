# frozen_string_literal: true

module Security
  module ScanResultPolicies
    # Re-evaluates scan_finding approval rules (pre-existing and newly-detected states)
    # for every open merge request in a project. Enqueued when a vulnerability is triaged
    # (dismissed / resolved / etc.), because pre-existing-state rules are scoped to
    # the project's vulnerabilities rather than to a single pipeline or merge request,
    # so the affected merge requests cannot be resolved from the triaged record alone.
    #
    # Deduplicated on project_id so a burst of triage actions collapses into a single
    # sweep. It fans out to both per-merge-request evaluators: one for pre-existing-state
    # rules and one for newly-detected-state rules. Both are idempotent.
    # The newly-detected re-evaluation only runs for merge requests with a failed violation on a
    # newly-detected rule with non-default states, so a triage never re-evaluates a merge request
    # those rules don't block or can't unblock.
    #
    # See https://gitlab.com/gitlab-org/gitlab/-/issues/560563
    # and https://gitlab.com/gitlab-org/gitlab/-/issues/627887
    class SyncProjectPreexistingStatesApprovalRulesWorker
      include ApplicationWorker

      idempotent!
      deduplicate :until_executing, including_scheduled: true
      data_consistency :delayed
      concurrency_limit -> { 200 }

      queue_namespace :security_scans
      feature_category :security_policy_management

      # Only scan_finding rules depend on vulnerability state; license_scanning rules
      # are unaffected by vulnerability triage, so they are intentionally excluded.
      REPORT_TYPES = [:scan_finding].freeze

      def perform(project_id)
        project = Project.find_by_id(project_id)
        return unless project
        # Cheap, indexed guard: skip projects that have no approval policy, so a triage
        # in a project without policies does not scan its open merge requests.
        return unless project.approval_policies.exists?

        project.merge_requests.opened.with_approval_rules_by_report_types(REPORT_TYPES).each_batch do |batch|
          batch.each do |merge_request|
            Security::ScanResultPolicies::SyncPreexistingStatesApprovalRulesWorker.perform_async(merge_request.id)
          end

          blocked_ids = blocked_merge_request_ids(batch)
          next if blocked_ids.empty?

          batch.id_in(blocked_ids).preload_head_pipeline_and_latest_diff.each do |merge_request|
            sync_newly_detected_states_approvals(merge_request)
          end
        end
      end

      private

      # MRs whose newly-detected scan_finding rule has a failed violation. Skipped is left out: it only
      # outlives re-evaluation when reports were never ingested. Empty or default states are excluded too,
      # as UpdateApprovalsService#dismissed_filter_for is nil for them, so a triage can't change the result.
      # rubocop:disable CodeReuse/ActiveRecord -- batch-scoped lookup, not a reusable abstraction
      def blocked_merge_request_ids(batch)
        rules = ApprovalMergeRequestRule.arel_table
        violations = Security::ScanResultPolicyViolation.arel_table
        blocking_violation = Security::ScanResultPolicyViolation.failed
          .where(violations[:merge_request_id].eq(rules[:merge_request_id]))
          .where(violations[:approval_policy_rule_id].eq(rules[:approval_policy_rule_id]))

        ApprovalMergeRequestRule
          .scan_finding
          .for_merge_requests(batch.map(&:id))
          .where(
            "approval_merge_request_rules.vulnerability_states && ARRAY[:newly_detected]::text[] AND NOT " \
              "(approval_merge_request_rules.vulnerability_states @> ARRAY[:defaults]::text[] AND " \
              "approval_merge_request_rules.vulnerability_states <@ ARRAY[:defaults]::text[])",
            newly_detected: ApprovalMergeRequestRule::NEWLY_DETECTED_STATUSES,
            defaults: ApprovalMergeRequestRule::DEFAULT_VULNERABILITY_STATUSES
          )
          .where(blocking_violation.arel.exists)
          .distinct
          .pluck(:merge_request_id)
          .to_set
      end
      # rubocop:enable CodeReuse/ActiveRecord

      # Rules with newly-detected states are evaluated only by UpdateApprovalsService, which
      # SyncPreexistingStatesApprovalRulesWorker skips. It already ignores findings whose
      # vulnerability is dismissed, so it just needs to run against the MR's head pipeline.
      def sync_newly_detected_states_approvals(merge_request)
        head_pipeline = merge_request.diff_head_pipeline
        # A running pipeline re-syncs on completion; evaluating it now would skip the scan
        # completion and presence checks and could pass on partial findings.
        return unless head_pipeline&.complete_or_manual?
        # Evaluating before ingestion sees no findings; ReportsIngestedEvent triggers it instead.
        return if within_ingestion_wait?(head_pipeline) && ::Security::Scan.ingestion_pending?(head_pipeline)

        Security::ScanResultPolicies::SyncMergeRequestApprovalsWorker.perform_async(head_pipeline.id, merge_request.id)
      end

      # ingestion_pending? stays true when ingestion stalled or stored no scans (a CycloneDX-only
      # pipeline), so past the wait no ReportsIngestedEvent follows and skipping would never sync.
      def within_ingestion_wait?(pipeline)
        # Pipelines blocked on manual jobs have no finished_at; updated_at approximates when they became manual.
        completed_at = pipeline.manual? ? pipeline.updated_at : pipeline.finished_at
        completed_at.present? && completed_at >= UnblockPendingMergeRequestViolationsWorker::MAX_INGESTION_WAIT.ago
      end
    end
  end
end
