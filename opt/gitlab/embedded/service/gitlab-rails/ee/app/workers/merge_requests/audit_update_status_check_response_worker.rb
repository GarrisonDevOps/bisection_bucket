# frozen_string_literal: true

module MergeRequests
  class AuditUpdateStatusCheckResponseWorker
    include ApplicationWorker

    data_consistency :sticky

    feature_category :compliance_management
    urgency :low
    deduplicate :until_executing
    idempotent!

    defer_on_database_health_signal :gitlab_main, [:project_audit_events], 1.minute

    # Audit stream to external destination with HTTP request if configured
    worker_has_external_dependencies!

    def perform(status_check_response_ids = [])
      responses = MergeRequests::StatusCheckResponse.id_in(status_check_response_ids)

      responses.find_each do |response|
        ::MergeRequests::StatusCheckResponses::AuditUpdateResponseService.new(response).execute
      end
    end
  end
end
