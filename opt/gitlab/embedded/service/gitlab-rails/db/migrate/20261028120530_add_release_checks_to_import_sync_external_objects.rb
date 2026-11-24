# frozen_string_literal: true

class AddReleaseChecksToImportSyncExternalObjects < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  TABLE_NAME = :import_sync_external_objects
  INDEX_NAME = 'idx_import_sync_external_objects_on_release_id'
  LOCAL_RECORD_CONSTRAINT = 'chk_import_sync_external_objects_one_local_record'
  OLD_LOCAL_RECORD_CHECK = 'num_nonnulls(issue_id, merge_request_id, note_id) = 1'
  NEW_LOCAL_RECORD_CHECK = 'num_nonnulls(issue_id, merge_request_id, note_id, release_id) = 1'

  def up
    add_concurrent_index TABLE_NAME, :release_id, unique: true, where: 'release_id IS NOT NULL', name: INDEX_NAME

    remove_check_constraint TABLE_NAME, LOCAL_RECORD_CONSTRAINT
    add_check_constraint TABLE_NAME, NEW_LOCAL_RECORD_CHECK, LOCAL_RECORD_CONSTRAINT
  end

  def down
    remove_check_constraint TABLE_NAME, LOCAL_RECORD_CONSTRAINT
    add_check_constraint TABLE_NAME, OLD_LOCAL_RECORD_CHECK, LOCAL_RECORD_CONSTRAINT

    remove_concurrent_index_by_name TABLE_NAME, INDEX_NAME
  end
end
