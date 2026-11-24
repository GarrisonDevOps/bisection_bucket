# frozen_string_literal: true

class AddReleaseIdToImportSyncExternalObjects < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :import_sync_external_objects, :release_id, :bigint
  end
end
