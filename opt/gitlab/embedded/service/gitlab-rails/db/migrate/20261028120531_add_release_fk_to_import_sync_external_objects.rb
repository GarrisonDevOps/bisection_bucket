# frozen_string_literal: true

class AddReleaseFkToImportSyncExternalObjects < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  def up
    # rubocop:disable Migration/ForeignKeysToDestroyServiceTables -- Releases::DestroyService declares handles_removal_of :import_sync_external_objects
    add_concurrent_foreign_key :import_sync_external_objects, :releases, column: :release_id, on_delete: :cascade
    # rubocop:enable Migration/ForeignKeysToDestroyServiceTables
  end

  def down
    with_lock_retries do
      remove_foreign_key_if_exists :import_sync_external_objects, column: :release_id
    end
  end
end
