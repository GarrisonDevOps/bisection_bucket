# frozen_string_literal: true

module MergeRequests
  class NotifyApproversWorker
    include ApplicationWorker

    data_consistency :delayed
    sidekiq_options retry: true
    feature_category :code_review_workflow
    urgency :low
    worker_resource_boundary :cpu
    idempotent!

    def perform(merge_request_id)
      merge_request = MergeRequest.find_by_id(merge_request_id)

      unless merge_request
        logger.info(structured_payload(message: 'Merge request not found.', merge_request_id: merge_request_id))
        return
      end

      merge_request.notify_approvers
    end
  end
end
