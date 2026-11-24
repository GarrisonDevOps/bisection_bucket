# frozen_string_literal: true

class AddCredentialTypeToImportSyncRepositories < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    # 0 = oauth (every existing row), 1 = personal_access_token
    add_column :import_sync_repositories, :credential_type, :smallint, default: 0, null: false
  end
end
