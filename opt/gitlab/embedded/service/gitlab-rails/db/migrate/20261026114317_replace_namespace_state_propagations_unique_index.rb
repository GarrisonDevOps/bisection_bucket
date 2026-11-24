# frozen_string_literal: true

class ReplaceNamespaceStatePropagationsUniqueIndex < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!

  milestone '19.6'

  TABLE_NAME = :namespace_state_propagations
  NEW_INDEX_NAME = 'idx_namespace_state_propagations_unique_processing'
  OLD_INDEX_NAME = 'idx_namespace_state_propagations_unique_pending_processing'

  def up
    add_concurrent_index TABLE_NAME, :namespace_id, unique: true, where: 'status = 1', name: NEW_INDEX_NAME
    remove_concurrent_index_by_name TABLE_NAME, OLD_INDEX_NAME
  end

  # no-op: the queue can hold several pending records with the same namespace and target state,
  # so recreating the old unique index would fail. Re-add it in a separate migration if needed.
  def down; end
end
