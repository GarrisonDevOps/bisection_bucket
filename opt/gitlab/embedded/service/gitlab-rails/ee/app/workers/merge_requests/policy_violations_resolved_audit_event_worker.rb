# frozen_string_literal: true

module MergeRequests
  class PolicyViolationsResolvedAuditEventWorker
    include ApplicationWorker

    data_consistency :sticky

    feature_category :security_policy_management
    urgency :low
    idempotent!
    deduplicate :until_executed
    defer_on_database_health_signal :gitlab_main, [:project_audit_events], 1.minute

    # Audit stream to external destination with HTTP request if configured
    worker_has_external_dependencies!

    def perform(merge_request_id)
      merge_request = MergeRequest.find_by_id(merge_request_id)
      unless merge_request
        logger.info structured_payload(message: 'Merge request not found.', merge_request_id: merge_request_id)
        return
      end

      PolicyViolationsResolvedAuditEventService.new(merge_request).execute
    end
  end
end
