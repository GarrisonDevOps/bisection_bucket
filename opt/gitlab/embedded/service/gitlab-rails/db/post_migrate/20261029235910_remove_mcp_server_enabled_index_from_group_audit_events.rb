# frozen_string_literal: true

class RemoveMcpServerEnabledIndexFromGroupAuditEvents < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::PartitioningMigrationHelpers

  milestone '19.6'

  disable_ddl_transaction!

  TABLE_NAME = :group_audit_events
  INDEX_NAME = 'tmp_idx_group_audit_events_on_group_id_created_at_mcp_enabled'
  COLUMNS = [:group_id, :created_at, :id]
  WHERE_CLAUSE = "event_name = 'mcp_server_enabled_updated'"

  def up
    unprepare_partitioned_async_index_by_name(TABLE_NAME, INDEX_NAME)

    partitions.each do |partition|
      # rubocop:disable Migration/RemoveIndex -- remove_concurrent_index_by_name refuses partitions; this drops concurrently
      remove_index(
        partition.identifier,
        name: generated_index_name(partition.identifier, INDEX_NAME),
        algorithm: :concurrently,
        if_exists: true
      )
      # rubocop:enable Migration/RemoveIndex
    end
  end

  def down
    prepare_partitioned_async_index(TABLE_NAME, COLUMNS, name: INDEX_NAME, where: WHERE_CLAUSE)
  end

  private

  def partitions
    find_partitioned_table(TABLE_NAME).postgres_partitions.order(:name)
  end
end
