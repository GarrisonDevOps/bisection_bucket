# frozen_string_literal: true

class RemoveDuplicateAnalyticsDevopsAdoptionSnapshots < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  restrict_gitlab_migration gitlab_schema: :gitlab_main_org
  disable_ddl_transaction!

  BATCH_SIZE = 1_000

  # A row is stale when another row for the same namespace and month was recorded later
  # (or has a higher id at the same recorded_at), so the newest row per group survives.
  STALE_ROW_CONDITION = <<~SQL
    EXISTS (
      SELECT 1
      FROM analytics_devops_adoption_snapshots newer
      WHERE newer.namespace_id = analytics_devops_adoption_snapshots.namespace_id
        AND newer.end_time = analytics_devops_adoption_snapshots.end_time
        AND (newer.recorded_at, newer.id) > (analytics_devops_adoption_snapshots.recorded_at, analytics_devops_adoption_snapshots.id)
    )
  SQL

  def up
    define_batchable_model('analytics_devops_adoption_snapshots').each_batch(of: BATCH_SIZE) do |batch|
      batch.where(STALE_ROW_CONDITION).delete_all
    end
  end

  def down
    # no-op: the deleted rows cannot be recreated; the newest snapshot per namespace and month was kept
  end
end
