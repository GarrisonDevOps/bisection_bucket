# frozen_string_literal: true

class AddIndexOnVerifiedAtToSnippetRepositoryRegistry < Gitlab::Database::Migration[2.2]
  disable_ddl_transaction!

  milestone '17.9'

  TABLE = :snippet_repository_registry
  INDEX = 'index_snippet_repository_registry_on_verified_at'

  def up
    add_concurrent_index TABLE, :verified_at, name: INDEX
  end

  def down
    remove_concurrent_index_by_name TABLE, INDEX
  end
end
