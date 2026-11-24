# frozen_string_literal: true

class QueueDeleteUploadsLooseFkDeletedRecords < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  restrict_gitlab_migration gitlab_schema: :gitlab_main_cell_local

  MIGRATION = "DeleteUploadsLooseFkDeletedRecords"
  # Larger than the defaults because each sub-batch is a PK-range delete of
  # bookkeeping rows with no FK cascades, and the backlog is ~44M rows.
  BATCH_SIZE = 10_000
  SUB_BATCH_SIZE = 1_000

  def up
    queue_batched_background_migration(
      MIGRATION,
      :loose_foreign_keys_deleted_records,
      :id,
      batch_size: BATCH_SIZE,
      sub_batch_size: SUB_BATCH_SIZE
    )
  end

  def down
    delete_batched_background_migration(MIGRATION, :loose_foreign_keys_deleted_records, :id, [])
  end
end
