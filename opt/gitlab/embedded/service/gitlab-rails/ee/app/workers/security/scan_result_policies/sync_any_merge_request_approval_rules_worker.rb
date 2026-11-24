# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class SyncAnyMergeRequestApprovalRulesWorker
      include ApplicationWorker

      idempotent!
      deduplicate :until_executed, if_deduplicated: :reschedule_once
      data_consistency :always
      sidekiq_options retry: true
      urgency :low
      concurrency_limit -> { 200 }
      concurrency_limit_scope :root_namespace, max_percentage: 0.5,
        enabled: -> {
          Feature.enabled?(:sync_any_merge_request_approval_rules_worker_concurrency_limit_scope, :instance)
        }

      feature_category :security_policy_management

      def perform(merge_request_id)
        merge_request = MergeRequest.find_by_id(merge_request_id)

        return unless merge_request

        Security::ScanResultPolicies::SyncAnyMergeRequestRulesService.new(merge_request).execute
      end
    end
  end
end
