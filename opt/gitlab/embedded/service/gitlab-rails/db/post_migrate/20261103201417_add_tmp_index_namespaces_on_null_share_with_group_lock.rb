# frozen_string_literal: true

class AddTmpIndexNamespacesOnNullShareWithGroupLock < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  INDEX_NAME = 'tmp_index_namespaces_on_id_where_share_with_group_lock_null'

  # Temporary index for the backfill in BackfillNullShareWithGroupLockOnNamespaces, removed in
  # RemoveTmpIndexNamespacesOnNullShareWithGroupLock. https://gitlab.com/gitlab-org/gitlab/-/work_items/637877
  def up
    # rubocop:disable Migration/PreventIndexCreation -- https://gitlab.com/gitlab-org/database-team/team-tasks/-/work_items/693
    add_concurrent_index :namespaces, :id, where: 'share_with_group_lock IS NULL', name: INDEX_NAME
    # rubocop:enable Migration/PreventIndexCreation
  end

  def down
    remove_concurrent_index_by_name :namespaces, INDEX_NAME
  end
end
