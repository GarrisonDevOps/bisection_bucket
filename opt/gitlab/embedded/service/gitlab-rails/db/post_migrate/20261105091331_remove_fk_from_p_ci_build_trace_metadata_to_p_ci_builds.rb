# frozen_string_literal: true

class RemoveFkFromPCiBuildTraceMetadataToPCiBuilds < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::PartitioningMigrationHelpers

  disable_ddl_transaction!
  milestone '19.6'

  SOURCE_TABLE = :p_ci_build_trace_metadata
  TARGET_TABLE = :p_ci_builds
  FK_NAME = :fk_rails_aebc78111f_p

  def up
    remove_partitioned_foreign_key SOURCE_TABLE, TARGET_TABLE,
      name: FK_NAME, reverse_lock_order: true
  end

  def down
    add_concurrent_partitioned_foreign_key SOURCE_TABLE, TARGET_TABLE,
      column: %i[partition_id build_id],
      target_column: %i[partition_id id],
      name: FK_NAME,
      on_update: :cascade,
      on_delete: :cascade,
      reverse_lock_order: true
  end
end
