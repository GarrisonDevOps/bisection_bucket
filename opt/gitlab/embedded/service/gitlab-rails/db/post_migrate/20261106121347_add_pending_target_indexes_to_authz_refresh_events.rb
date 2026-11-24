# frozen_string_literal: true

class AddPendingTargetIndexesToAuthzRefreshEvents < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::PartitioningMigrationHelpers

  disable_ddl_transaction!
  milestone '19.6'

  TABLE_NAME = :authz_refresh_events
  TARGET_INDEX = 'index_authz_refresh_events_pending_on_target'
  SHARE_SCOPE_INDEX = 'index_authz_refresh_events_pending_share_change_scope'

  def up
    add_concurrent_partitioned_index(TABLE_NAME, [:target_type, :target_id, :scope_id],
      where: 'status = 1', name: TARGET_INDEX)
    add_concurrent_partitioned_index(TABLE_NAME, :scope_id,
      where: 'target_type = 7 AND status = 1', name: SHARE_SCOPE_INDEX)
  end

  def down
    remove_concurrent_partitioned_index_by_name(TABLE_NAME, SHARE_SCOPE_INDEX)
    remove_concurrent_partitioned_index_by_name(TABLE_NAME, TARGET_INDEX)
  end
end
