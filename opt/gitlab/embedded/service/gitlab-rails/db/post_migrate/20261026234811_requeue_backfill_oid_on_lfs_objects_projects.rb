# frozen_string_literal: true

class RequeueBackfillOidOnLfsObjectsProjects < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  restrict_gitlab_migration gitlab_schema: :gitlab_main_org

  MIGRATION = 'BackfillOidOnLfsObjectsProjects'
  # Keep sub-batch UPDATEs under the 1s BBM query guideline; the batch
  # optimizer grows batch_size from here if jobs stay well under interval.
  #
  BATCH_SIZE = 1_000
  SUB_BATCH_SIZE = 250

  # The finalized BBM cannot be re-queued directly (the dedup check matches
  # regardless of status), so delete the finalized record and re-queue the same
  # job class to mop up rows that leaked a NULL oid after its range was frozen.
  #
  def up
    delete_batched_background_migration(MIGRATION, :lfs_objects_projects, :id, [])

    queue_batched_background_migration(
      MIGRATION,
      :lfs_objects_projects,
      :id,
      batch_size: BATCH_SIZE,
      sub_batch_size: SUB_BATCH_SIZE
    )
  end

  def down
    delete_batched_background_migration(MIGRATION, :lfs_objects_projects, :id, [])
  end
end
