# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class AuditWarnModeMergeRequestApprovalSettingsWorker
      include ApplicationWorker

      data_consistency :sticky
      idempotent!
      deduplicate :until_executed
      concurrency_limit -> { 200 }
      feature_category :security_policy_management

      def perform(merge_request_id)
        merge_request = MergeRequest.find_by_id(merge_request_id) || return

        return unless feature_enabled?(merge_request.project)
        return unless eligible_to_run?(merge_request)

        Security::ScanResultPolicies::AuditWarnModeMergeRequestApprovalSettingsOverridesService
          .new(merge_request)
          .execute
      end

      private

      def feature_enabled?(project)
        ::Security::PolicyAvailability.available?(project, :security_orchestration_policies)
      end

      def eligible_to_run?(merge_request)
        return false unless merge_request.open?

        merge_request.running_scan_result_policy_violations.none?
      end
    end
  end
end
