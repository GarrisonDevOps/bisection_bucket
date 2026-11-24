# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class CleanupMergeRequestViolationsWorker
      include Gitlab::EventStore::Subscriber
      include ::Security::ScanResultPolicies::PolicyLogger

      feature_category :security_policy_management
      data_consistency :sticky
      idempotent!

      def handle_event(event)
        merge_request = MergeRequest.find_by_id(event.data[:merge_request_id]) || return
        project = merge_request.project
        return unless ::Security::PolicyAvailability.any_available?(project)

        return if merge_request.scan_result_policy_violations.none?

        if event.is_a?(::MergeRequests::MergedEvent)
          log_running_violations_after_merge(merge_request)
          audit_merged_with_policy_violations(merge_request)
          preserve_security_policy_dismissals(merge_request)
        end

        merge_request.scan_result_policy_violations.delete_all(:delete_all)
      end

      private

      def log_running_violations_after_merge(merge_request)
        running_violations = merge_request.running_scan_result_policy_violations
        return if running_violations.none?

        log_policy_evaluation('post_merge', 'Running scan result policy violations after merge',
          project: merge_request.project,
          merge_request_id: merge_request.id,
          merge_request_iid: merge_request.iid,
          head_pipeline_id: merge_request.diff_head_pipeline&.id,
          violation_ids: running_violations.map(&:id),
          scan_result_policy_ids: running_violations.filter_map(&:scan_result_policy_id),
          approval_policy_rule_ids: running_violations.filter_map(&:approval_policy_rule_id)
        )
      end

      def audit_merged_with_policy_violations(merge_request)
        MergeRequests::MergedWithPolicyViolationsAuditEventService.new(merge_request).execute
      end

      def preserve_security_policy_dismissals(merge_request)
        merge_request.preserve_open_policy_dismissals!
      end
    end
  end
end
