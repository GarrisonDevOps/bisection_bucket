# frozen_string_literal: true

module Security
  class SyncTrackedContextTraversalIdsWorker
    include ApplicationWorker

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    # rubocop: disable SidekiqLoadBalancing/WorkerDataConsistency -- Needs fresh traversal_ids from primary database
    data_consistency :always
    # rubocop: enable SidekiqLoadBalancing/WorkerDataConsistency

    # Group transfers fan this out to one job per project in the group, so the
    # burst is unbounded without a limit here.
    concurrency_limit -> { 200 }

    feature_category :vulnerability_management

    defer_on_database_health_signal :gitlab_sec, [:security_project_tracked_contexts], 1.minute

    def perform(project_id)
      ::Security::ProjectTrackedContexts::SyncTraversalIdsService.execute(project_id)
    end
  end
end
