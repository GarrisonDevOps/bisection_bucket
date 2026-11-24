# frozen_string_literal: true

module Ci
  class BuildTraceChunkFlushWorker
    include ApplicationWorker
    include PipelineBackgroundQueue

    urgency :high
    max_concurrency_limit_percentage 0.45
    # GitLab.com runs this on urgent-other. 20% of the 45% limit caps one top-level group at 9%
    # of the shard's threads.
    concurrency_limit_scope(:root_namespace, max_percentage: 0.2,
      enabled: -> { Feature.enabled?(:ci_pipeline_execution_concurrency_limit_scope_wave_three, :instance) })
    data_consistency :sticky
    idempotent!
    deduplicate :until_executed
    sidekiq_options retry: false

    def perform(id)
      ::Ci::BuildTraceChunk.find_by_id(id).try(&:persist_data!)
    end
  end
end
