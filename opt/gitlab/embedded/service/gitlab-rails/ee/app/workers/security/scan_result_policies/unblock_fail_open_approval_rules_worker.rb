# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class UnblockFailOpenApprovalRulesWorker
      include ApplicationWorker

      feature_category :security_policy_management

      data_consistency :sticky

      idempotent!

      def perform(merge_request_id)
        merge_request = MergeRequest.find_by_id(merge_request_id) || return

        Security::ScanResultPolicies::UnblockFailOpenApprovalRulesService
          .new(merge_request: merge_request)
          .execute
      end
    end
  end
end
