# frozen_string_literal: true

module Security
  class SyncPolicyViolationCommentWorker
    include ApplicationWorker
    include ::Security::ScanResultPolicies::PolicyViolationCommentGenerator

    idempotent!
    data_consistency :sticky
    feature_category :security_policy_management

    def perform(merge_request_id)
      merge_request = MergeRequest.find_by_id(merge_request_id)

      unless merge_request
        logger.info(structured_payload(message: 'Merge request not found.', merge_request_id: merge_request_id))
        return
      end

      return unless ::Security::PolicyAvailability.any_available?(merge_request.project)

      approval_rules = merge_request.approval_rules.report_approver
      return if approval_rules.blank?

      generate_policy_bot_comment(merge_request)
    end
  end
end
