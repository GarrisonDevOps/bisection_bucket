# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class FallbackBehaviorTrackingWorker
      include ApplicationWorker

      feature_category :security_policy_management
      data_consistency :sticky
      idempotent!

      def perform(merge_request_id)
        merge_request = MergeRequest.find_by_id(merge_request_id) || return

        Security::ScanResultPolicies::FallbackBehaviorTrackingService.new(merge_request).execute
      end
    end
  end
end
