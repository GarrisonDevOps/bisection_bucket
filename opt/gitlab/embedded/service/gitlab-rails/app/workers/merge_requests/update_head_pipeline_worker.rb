# frozen_string_literal: true

module MergeRequests
  class UpdateHeadPipelineWorker
    include Gitlab::EventStore::Subscriber

    feature_category :code_review_workflow
    urgency :high
    worker_resource_boundary :cpu
    data_consistency :always

    idempotent!

    def handle_event(event)
      pipeline_creation_request = event.data[:pipeline_creation_request]

      pipeline = Ci::Pipeline.in_partition(event.data[:partition_id]).find_by_id(event.data[:pipeline_id])
      return unless pipeline

      merge_requests = pipeline.all_merge_requests.opened.to_a
      merge_requests.each(&:update_head_pipeline)

      ::Ci::PipelineCreation::Requests.succeeded(pipeline_creation_request, pipeline.id)

      process_auto_merge(pipeline) if pipeline_creation_request.present?
    end

    private

    # A pipeline that completed before its request finished already ran auto-merge while the request
    # still blocked the merge, so run it again now that the request is gone. Both inputs are read here,
    # after the deletion: anything that changes later no longer sees a request and runs itself.
    def process_auto_merge(pipeline)
      return unless pipeline.reset.complete?
      return unless pipeline.all_merge_requests.with_auto_merge_enabled.exists?

      AutoMergeProcessWorker.perform_async({ 'pipeline_id' => pipeline.id })
    end
  end
end
