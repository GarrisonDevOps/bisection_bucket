# frozen_string_literal: true

module MergeRequests
  # rubocop: disable Scalability/IdempotentWorker -- EventStore::Subscriber inlcudes idempotent
  class ProcessMergeAuditEventWorker
    include Gitlab::EventStore::Subscriber # adds idempotent!

    data_consistency :always
    feature_category :compliance_management
    urgency :low

    # Audit may stream to external destination with HTTP request if configured for the group
    worker_has_external_dependencies!

    def handle_event(event)
      @event = event

      unless merge_request
        logger.info structured_payload(message: 'Merge request not found.', merge_request_id: merge_request_id)
        return
      end

      ::MergeRequests::MergeAuditEventService.new(merge_request: merge_request).execute
    end

    private

    def merge_request_id
      @event.data[:merge_request_id]
    end

    def merge_request
      @merge_request ||= MergeRequest.find_by_id merge_request_id
    end
  end
  # rubocop: enable Scalability/IdempotentWorker
end
