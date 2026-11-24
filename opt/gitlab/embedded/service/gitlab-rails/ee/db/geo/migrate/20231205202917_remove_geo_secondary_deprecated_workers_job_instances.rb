# frozen_string_literal: true

class RemoveGeoSecondaryDeprecatedWorkersJobInstances < Gitlab::Database::Migration[2.2]
  DEPRECATED_JOB_CLASSES = %w[
    Geo::Batch::ProjectRegistrySchedulerWorker
    Geo::HashedStorageMigrationWorker
    Geo::ProjectSyncWorker
    Geo::RenameRepositoryWorker
    Geo::RepositoriesCleanUpWorker
    Geo::RepositoryCleanupWorker
    Geo::RepositoryShardSyncWorker
    Geo::RepositorySyncWorker
    Geo::RepositoryVerification::Secondary::SchedulerWorker
    Geo::RepositoryVerification::Secondary::ShardWorker
    Geo::Scheduler::Secondary::PerShardSchedulerWorker
    GeoRepositoryDestroyWorker
  ]

  disable_ddl_transaction!

  milestone '16.7'

  def up
    sidekiq_remove_jobs(job_klasses: DEPRECATED_JOB_CLASSES)
  end

  def down
    # This migration removes any instances of deprecated workers and cannot be undone.
  end
end
