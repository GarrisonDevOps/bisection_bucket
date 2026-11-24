# frozen_string_literal: true

class RemoveFkAiEventsCountsToOrganizations < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::PartitioningMigrationHelpers::ForeignKeyHelpers

  disable_ddl_transaction!
  milestone '19.7'

  SOURCE_TABLE_NAME = :ai_events_counts
  TARGET_TABLE_NAME = :organizations
  FK_NAME = :fk_rails_99a3f4a8f1

  def up
    with_lock_retries do
      remove_foreign_key_if_exists(SOURCE_TABLE_NAME, TARGET_TABLE_NAME, name: FK_NAME)
    end
  end

  def down
    add_concurrent_partitioned_foreign_key(
      SOURCE_TABLE_NAME,
      TARGET_TABLE_NAME,
      column: :organization_id,
      on_delete: :cascade,
      name: FK_NAME
    )
  end
end
