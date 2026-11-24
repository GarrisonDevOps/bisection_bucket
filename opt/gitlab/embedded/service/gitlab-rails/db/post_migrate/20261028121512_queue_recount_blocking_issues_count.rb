# frozen_string_literal: true

class QueueRecountBlockingIssuesCount < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  restrict_gitlab_migration gitlab_schema: :gitlab_main_org

  MIGRATION = "RecountBlockingIssuesCount"
  BATCH_SIZE = 10_000
  SUB_BATCH_SIZE = 500

  def up
    queue_batched_background_migration(
      MIGRATION,
      :issues,
      :id,
      batch_size: BATCH_SIZE,
      sub_batch_size: SUB_BATCH_SIZE
    )
  end

  def down
    delete_batched_background_migration(MIGRATION, :issues, :id, [])
  end
end
