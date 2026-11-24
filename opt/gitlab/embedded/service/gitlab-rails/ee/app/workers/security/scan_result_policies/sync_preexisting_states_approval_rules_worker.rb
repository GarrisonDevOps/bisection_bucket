# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class SyncPreexistingStatesApprovalRulesWorker
      include ApplicationWorker

      idempotent!
      deduplicate :until_executed, if_deduplicated: :reschedule_once
      data_consistency :always
      concurrency_limit -> { 200 }

      queue_namespace :security_scans
      feature_category :security_policy_management

      def perform(merge_request_id)
        merge_request = MergeRequest.find_by_id(merge_request_id)
        return unless merge_request

        Security::ScanResultPolicies::SyncPreexistingStatesApprovalRulesService.new(merge_request).execute
        Security::ScanResultPolicies::UpdateLicenseApprovalsService.new(merge_request, nil, true).execute
      end
    end
  end
end
