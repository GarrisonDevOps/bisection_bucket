# frozen_string_literal: true

module ComplianceManagement
  class TimeoutPendingStatusCheckResponsesWorker
    include ApplicationWorker

    # This worker does not schedule other workers that require context.
    include CronjobQueue # rubocop:disable Scalability/CronWorkerContext

    idempotent!
    feature_category :compliance_management
    data_consistency :always
    urgency :high

    def perform
      ::MergeRequests::StatusCheckResponse.pending.timeout_eligible.each_batch do |batch|
        record_ids = batch.pluck_primary_key
        batch.update_all(status: 'failed')

        ::MergeRequests::AuditUpdateStatusCheckResponseWorker.perform_async(record_ids)
      end
    end
  end
end
