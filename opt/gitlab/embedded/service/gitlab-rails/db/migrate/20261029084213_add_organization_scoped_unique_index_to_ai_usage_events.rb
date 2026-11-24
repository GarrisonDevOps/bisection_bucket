# frozen_string_literal: true

class AddOrganizationScopedUniqueIndexToAiUsageEvents < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::PartitioningMigrationHelpers

  disable_ddl_transaction!
  milestone '19.6'

  TABLE_NAME = :ai_usage_events
  INDEX_NAME = 'idx_ai_usage_events_org_uniqueness'

  # A regular migration, not post-deploy: the write buffer's upsert targets this index, so it
  # must exist before the new code runs. The old index is dropped in a later release.
  def up
    add_concurrent_partitioned_index(
      TABLE_NAME,
      %w[namespace_id user_id event timestamp organization_id],
      name: INDEX_NAME,
      unique: true,
      nulls_not_distinct: true
    )
  end

  def down
    remove_concurrent_partitioned_index_by_name(TABLE_NAME, INDEX_NAME)
  end
end
