# frozen_string_literal: true

class QueueMarkDuplicateDefaultTrackedContextsAsNonDefault < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  restrict_gitlab_migration gitlab_schema: :gitlab_sec

  MIGRATION = "MarkDuplicateDefaultTrackedContextsAsNonDefault"
  DELAY_INTERVAL = 2.minutes
  BATCH_SIZE = 100_000
  SUB_BATCH_SIZE = 2_500

  def up
    queue_batched_background_migration(
      MIGRATION,
      :security_project_tracked_contexts,
      :id,
      job_interval: DELAY_INTERVAL,
      batch_size: BATCH_SIZE,
      sub_batch_size: SUB_BATCH_SIZE
    )
  end

  def down
    delete_batched_background_migration(MIGRATION, :security_project_tracked_contexts, :id, [])
  end
end
