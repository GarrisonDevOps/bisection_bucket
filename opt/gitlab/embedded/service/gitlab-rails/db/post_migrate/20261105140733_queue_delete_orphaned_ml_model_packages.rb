# frozen_string_literal: true

class QueueDeleteOrphanedMlModelPackages < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  restrict_gitlab_migration gitlab_schema: :gitlab_main_org

  MIGRATION = "DeleteOrphanedMlModelPackages"
  BATCH_SIZE = 10_000
  SUB_BATCH_SIZE = 1_000

  def up
    queue_batched_background_migration(
      MIGRATION,
      :packages_packages,
      :id,
      batch_size: BATCH_SIZE,
      sub_batch_size: SUB_BATCH_SIZE
    )
  end

  def down
    delete_batched_background_migration(MIGRATION, :packages_packages, :id, [])
  end
end
