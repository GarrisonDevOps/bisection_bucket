# frozen_string_literal: true

module Security
  class GeneratePolicyViolationCommentWorker
    include ApplicationWorker

    idempotent!
    deduplicate :until_executed, if_deduplicated: :reschedule_once
    data_consistency :sticky
    feature_category :security_policy_management

    defer_on_database_health_signal :gitlab_main, [], 1.minute

    def perform(merge_request_id, _params = {})
      merge_request = MergeRequest.find_by_id(merge_request_id)

      unless merge_request
        logger.info(structured_payload(message: 'Merge request not found.', merge_request_id: merge_request_id))
        return
      end

      result = Security::ScanResultPolicies::GeneratePolicyViolationCommentService.new(merge_request).execute
      return unless result.error?

      log_message(result.message.join(', '), merge_request_id)
    end

    private

    def log_message(errors, merge_request_id)
      logger.warn(
        structured_payload(
          merge_request_id: merge_request_id,
          message: errors
        ))
    end
  end
end
