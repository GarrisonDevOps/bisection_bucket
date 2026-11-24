# frozen_string_literal: true

module Ci
  class DropPipelineWorker
    include ApplicationWorker

    data_consistency :always

    sidekiq_options retry: 3
    include PipelineQueue

    urgency :high

    idempotent!

    # GitLab.com runs this on urgent-other. 30% of its 35% default limit caps one banned user
    # at 10.5% of the shard's threads. Ci::DropPipelineForBlockedUserWorker inherits this scope
    # on low-urgency-ci-pipeline, where it is 7.5% per blocked user, and gets its own kill switch.
    concurrency_limit_scope(:user, max_percentage: 0.3,
      enabled: -> { Feature.enabled?(:ci_pipeline_execution_concurrency_limit_scope_wave_one, :instance) })

    def perform(pipeline_id, failure_reason)
      Ci::Pipeline.find_by_id(pipeline_id).try do |pipeline|
        Ci::DropPipelineService.new.execute(pipeline, failure_reason.to_sym)
      end
    end
  end
end
