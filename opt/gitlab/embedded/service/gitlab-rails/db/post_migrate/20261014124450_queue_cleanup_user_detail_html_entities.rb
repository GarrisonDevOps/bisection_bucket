# frozen_string_literal: true

class QueueCleanupUserDetailHtmlEntities < Gitlab::Database::Migration[2.3]
  milestone '19.6'

  restrict_gitlab_migration gitlab_schema: :gitlab_main_user

  MIGRATION = "CleanupUserDetailHtmlEntities"
  BATCH_SIZE = 10_000
  SUB_BATCH_SIZE = 1_000
  MAX_BATCH_SIZE = 10_000

  def up
    queue_batched_background_migration(
      MIGRATION,
      :user_details,
      :user_id,
      batch_size: BATCH_SIZE,
      sub_batch_size: SUB_BATCH_SIZE,
      max_batch_size: MAX_BATCH_SIZE
    )
  end

  def down
    delete_batched_background_migration(MIGRATION, :user_details, :user_id, [])
  end
end
