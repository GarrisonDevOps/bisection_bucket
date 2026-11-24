# frozen_string_literal: true

class AddIndexesOnFileRegistry < Gitlab::Database::Migration[2.2]
  milestone '17.5'

  disable_ddl_transaction!

  TABLE = :file_registry
  INDEX_STATE = 'index_file_registry_state'
  INDEX_FILE_ID = 'index_file_registry_file_id'

  def up
    add_concurrent_index TABLE, :state, name: INDEX_STATE
    add_concurrent_index TABLE, :file_id, name: INDEX_FILE_ID
  end

  def down
    remove_concurrent_index_by_name TABLE, INDEX_STATE
    remove_concurrent_index_by_name TABLE, INDEX_FILE_ID
  end
end
