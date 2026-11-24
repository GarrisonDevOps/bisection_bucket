# frozen_string_literal: true

class RemoveFkPCiBuildsPartitionOverridesToPCiBuilds < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::PartitioningMigrationHelpers::ForeignKeyHelpers

  disable_ddl_transaction!
  milestone '19.6'

  SOURCE_TABLE_NAME = :p_ci_builds_partition_overrides
  TARGET_TABLE_NAME = :p_ci_builds
  FK_NAME = :fk_rails_4b774ba747

  def up
    with_lock_retries do
      remove_foreign_key_if_exists(
        SOURCE_TABLE_NAME,
        TARGET_TABLE_NAME,
        name: FK_NAME,
        reverse_lock_order: true
      )
    end
  end

  def down
    add_concurrent_partitioned_foreign_key(
      SOURCE_TABLE_NAME,
      TARGET_TABLE_NAME,
      column: [:partition_id, :build_id],
      target_column: [:partition_id, :id],
      reverse_lock_order: true,
      on_update: :cascade,
      on_delete: :cascade,
      name: FK_NAME,
      validate: true
    )
  end
end
