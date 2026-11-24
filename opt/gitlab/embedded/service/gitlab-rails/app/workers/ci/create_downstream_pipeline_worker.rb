# frozen_string_literal: true

module Ci
  class CreateDownstreamPipelineWorker
    include ::ApplicationWorker
    include ::PipelineQueue

    sidekiq_options retry: 3
    worker_resource_boundary :cpu
    data_consistency :sticky
    urgency :low
    deduplicate :until_executed, if_deduplicated: :reschedule_once, including_scheduled: true
    # Not strictly idempotent (concurrent runs can create two downstream pipelines), but deduplication
    # only applies to idempotent workers. See https://gitlab.com/gitlab-org/gitlab/-/work_items/632905
    idempotent!

    # GitLab.com runs this on low-urgency-cpu-bound. 40% of its 25% default limit caps one
    # top-level group at 10% of the shard's threads.
    concurrency_limit_scope(:root_namespace, max_percentage: 0.4,
      enabled: -> { Feature.enabled?(:ci_pipeline_execution_concurrency_limit_scope_wave_one, :instance) })

    def perform(bridge_id)
      Gitlab::QueryLimiting.disable!('https://gitlab.com/gitlab-org/gitlab/-/issues/464668')

      ::Ci::Bridge.find_by_id(bridge_id).try do |bridge|
        result = ::Ci::CreateDownstreamPipelineService
          .new(bridge.project, bridge.user)
          .execute(bridge)

        if result.success?
          log_extra_metadata_on_done(:new_pipeline_id, result.payload.id)
        else
          log_extra_metadata_on_done(:create_error_message, result.message)
        end
      end
    end
  end
end
