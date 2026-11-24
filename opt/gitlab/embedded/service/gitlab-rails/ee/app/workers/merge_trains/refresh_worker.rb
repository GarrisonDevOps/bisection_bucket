# frozen_string_literal: true

module MergeTrains
  class RefreshWorker
    include ApplicationWorker

    data_consistency :always

    sidekiq_options retry: 3

    queue_namespace :auto_merge
    feature_category :merge_trains
    worker_resource_boundary :cpu

    # Required, since `MergeTrains::RefreshService#execute` is concurrent-unsafe
    deduplicate :until_executed, if_deduplicated: :reschedule_once
    idempotent!

    loggable_arguments 0, 1

    # GitLab.com runs this on low-urgency-cpu-bound. 40% of its 25% default limit caps one
    # top-level group at 10% of the shard's threads.
    concurrency_limit_scope(:root_namespace, max_percentage: 0.4,
      enabled: -> { Feature.enabled?(:ci_pipeline_execution_concurrency_limit_scope_wave_one, :instance) })

    def perform(target_project_id, target_branch)
      Gitlab::QueryLimiting.disable!('https://gitlab.com/gitlab-org/gitlab/-/issues/464678', new_threshold: 202)

      response = ::MergeTrains::RefreshService
        .new(target_project_id, target_branch)
        .execute

      log_hash_metadata_on_done(response.payload)
    end
  end
end
