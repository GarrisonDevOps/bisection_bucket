# frozen_string_literal: true

module Ci
  class ArchiveTraceWorker
    include ApplicationWorker

    idempotent!
    deduplicate :until_executed
    data_consistency :sticky

    sidekiq_options retry: 3
    # GitLab.com runs this on low-urgency-ci-pipeline. 60% clears the worker's peak there;
    # 15% of that caps one top-level group at 9% of the shard's threads.
    max_concurrency_limit_percentage 0.6
    concurrency_limit_scope(:root_namespace, max_percentage: 0.15,
      enabled: -> { Feature.enabled?(:ci_pipeline_execution_concurrency_limit_scope_wave_three, :instance) })
    include PipelineBackgroundQueue

    def perform(job_id)
      archivable_jobs = Ci::Build.without_archived_trace.eager_load_for_archiving_trace

      archivable_jobs.find_by_id(job_id).try do |job|
        Ci::ArchiveTraceService.new.execute(job, worker_name: self.class.name)
      end
    end
  end
end
