# frozen_string_literal: true

class QueueBackfillSecProjectMirrors < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  restrict_gitlab_migration gitlab_schema: :gitlab_main_org

  MIGRATION = "BackfillSecProjectMirrors"
  BATCH_SIZE = 50_000
  SUB_BATCH_SIZE = 1_000

  def up
    queue_batched_background_migration(
      MIGRATION,
      :projects,
      :id,
      batch_size: BATCH_SIZE,
      sub_batch_size: SUB_BATCH_SIZE
    )
  end

  def down
    delete_batched_background_migration(MIGRATION, :projects, :id, [])
  end
end
