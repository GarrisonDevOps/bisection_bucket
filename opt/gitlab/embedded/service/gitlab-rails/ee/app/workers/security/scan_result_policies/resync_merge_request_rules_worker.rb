# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class ResyncMergeRequestRulesWorker
      include ApplicationWorker

      idempotent!
      deduplicate :until_executed, if_deduplicated: :reschedule_once
      data_consistency :sticky
      urgency :low
      concurrency_limit -> { 200 }
      defer_on_database_health_signal :gitlab_main,
        [:approval_merge_request_rules, :scan_result_policy_violations], 1.minute

      feature_category :security_policy_management

      def perform(merge_request_id)
        merge_request = MergeRequest.find_by_id(merge_request_id)
        return unless merge_request&.opened?
        return unless merge_request.project.licensed_feature_available?(:security_orchestration_policies)

        sync_approval_rules(merge_request)

        merge_request.schedule_policy_synchronization
      end

      private

      # The check re-enqueues this worker on every evaluation, so Sidekiq retries only add churn.
      def sync_approval_rules(merge_request)
        ::MergeRequests::SyncReportApproverApprovalRules
          .new(merge_request)
          .execute(skip_authentication: true)
      rescue ActiveRecord::RecordInvalid => e
        Gitlab::ErrorTracking.track_exception(e, merge_request_id: merge_request.id)
      end
    end
  end
end
