# frozen_string_literal: true

# The group_group_links delete trigger looks up pending group membership events by scope, once per removed share.
class AddPendingMembershipScopeIndexToAuthzRefreshEvents < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::PartitioningMigrationHelpers

  disable_ddl_transaction!
  milestone '19.6'

  TABLE_NAME = :authz_refresh_events
  INDEX_NAME = 'index_authz_refresh_events_pending_membership_scope'

  def up
    add_concurrent_partitioned_index(TABLE_NAME, :scope_id, where: 'target_type = 3 AND status = 1', name: INDEX_NAME)
  end

  def down
    remove_concurrent_partitioned_index_by_name(TABLE_NAME, INDEX_NAME)
  end
end
