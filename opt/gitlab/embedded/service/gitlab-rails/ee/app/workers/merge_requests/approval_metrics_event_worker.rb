# frozen_string_literal: true

module MergeRequests
  class ApprovalMetricsEventWorker
    include Gitlab::EventStore::Subscriber

    data_consistency :sticky
    feature_category :code_review_workflow
    urgency :low
    idempotent!

    def handle_event(event)
      merge_request_id = event.data[:merge_request_id]
      approved_at = event.data[:approved_at]
      merge_request = MergeRequest.find_by_id(merge_request_id)

      return unless merge_request

      MergeRequest::ApprovalMetrics.refresh_last_approved_at(merge_request: merge_request,
        last_approved_at: approved_at)
    end
  end
end
