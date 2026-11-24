# frozen_string_literal: true

class RemoveIdxMrCleanupSchedulesOnMergeRequestId < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!

  milestone '19.6'

  TABLE_NAME = :merge_request_cleanup_schedules
  INDEX_NAME = 'index_merge_request_cleanup_schedules_on_merge_request_id'

  def up
    remove_concurrent_index_by_name TABLE_NAME, INDEX_NAME
  end

  def down
    add_concurrent_index TABLE_NAME, :merge_request_id, unique: true, name: INDEX_NAME
  end
end
