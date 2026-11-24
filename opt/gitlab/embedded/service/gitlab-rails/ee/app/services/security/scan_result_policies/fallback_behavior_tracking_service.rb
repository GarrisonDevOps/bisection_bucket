# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class FallbackBehaviorTrackingService
      include Gitlab::InternalEventsTracking

      EVENT_NAME = 'bypass_approvals_for_mr_approval_policy_when_policy_is_evaluated'

      def initialize(merge_request)
        @merge_request = merge_request
        @project = merge_request.project
        @head_pipeline = merge_request.diff_head_pipeline
        @approval_rules = policy_approval_rules
        @update_approvals_service = Security::ScanResultPolicies::UpdateApprovalsService
            .new(merge_request: merge_request, pipeline: head_pipeline)
      end

      def execute
        approval_rules.each { |rule| track?(rule) && (break track!) }
      end

      private

      attr_reader :merge_request,
        :project,
        :head_pipeline,
        :approval_rules,
        :update_approvals_service

      def policy_approval_rules
        merge_request.approval_rules.with_approval_policy_rule
      end

      def track!
        track_internal_event(
          EVENT_NAME,
          project: project
        )
      end

      def track?(approval_rule)
        policy_fails_open?(approval_rule) && (invalid?(approval_rule) || rule_failed_open?(approval_rule))
      end

      def policy_fails_open?(approval_rule)
        approval_rule.approval_policy_source&.fail_open?
      end

      def invalid?(approval_rule)
        ApprovalWrappedRule.wrap(approval_rule.merge_request, approval_rule).invalid_rule?
      end

      def rule_failed_open?(approval_rule)
        # Only track fail-open rules if:
        # * it relates to a (missing) security scan
        # * the rule unexpectedly still requires approvals once the MR was merged
        # * the rule never required approvals in the first place
        return false unless approval_rule.scan_finding? || approval_rule.license_scanning?
        return false if approval_rule.approvals_required?
        return false unless approval_rule.approval_project_rule&.approvals_required?

        # Track fail-open rules if:
        # * there can't be any security scans
        # * the rule relates to a security scan present for the target branch, but absent for the source branch
        return true unless head_pipeline&.can_store_security_reports?
        return true if approval_rule.scan_finding? && update_approvals_service.scan_missing?(approval_rule)

        false
      end
    end
  end
end
