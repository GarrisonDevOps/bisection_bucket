# frozen_string_literal: true

class QueueDeleteLegacyScanResultPolicyReads < Gitlab::Database::Migration[2.3]
  milestone '19.6'

  restrict_gitlab_migration gitlab_schema: :gitlab_main_org

  MIGRATION = "DeleteLegacyScanResultPolicyReads"
  BATCH_SIZE = 5_000
  SUB_BATCH_SIZE = 1_000

  def up
    queue_batched_background_migration(
      MIGRATION,
      :scan_result_policies,
      :id,
      batch_size: BATCH_SIZE,
      sub_batch_size: SUB_BATCH_SIZE
    )
  end

  def down
    delete_batched_background_migration(MIGRATION, :scan_result_policies, :id, [])
  end
end
