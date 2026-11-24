# frozen_string_literal: true

class RemoveTmpIndexNamespacesOnNullShareWithGroupLock < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  INDEX_NAME = 'tmp_index_namespaces_on_id_where_share_with_group_lock_null'

  def up
    remove_concurrent_index_by_name :namespaces, INDEX_NAME
  end

  def down
    add_concurrent_index :namespaces, :id, where: 'share_with_group_lock IS NULL', name: INDEX_NAME
  end
end
