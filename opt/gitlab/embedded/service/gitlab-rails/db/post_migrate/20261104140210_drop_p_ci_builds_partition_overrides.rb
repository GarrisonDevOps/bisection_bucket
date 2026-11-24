# frozen_string_literal: true

class DropPCiBuildsPartitionOverrides < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::PartitioningMigrationHelpers::TableManagementHelpers

  disable_ddl_transaction!
  milestone '19.6'

  TABLE_NAME = :p_ci_builds_partition_overrides

  def up
    with_lock_retries do
      drop_table TABLE_NAME, if_exists: true
    end
  end

  def down
    with_lock_retries do
      create_table(TABLE_NAME, id: false, options: 'PARTITION BY HASH (build_id)', if_not_exists: true) do |t|
        t.bigint :build_id, primary_key: true, null: false, default: nil
        t.bigint :partition_id, null: false
        t.bigint :project_id, null: false, index: true
      end
    end

    create_hash_partitions(TABLE_NAME, 3)
  end
end
