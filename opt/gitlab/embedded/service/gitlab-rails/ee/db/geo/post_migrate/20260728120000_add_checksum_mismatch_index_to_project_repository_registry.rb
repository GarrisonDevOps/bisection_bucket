# frozen_string_literal: true

class AddChecksumMismatchIndexToProjectRepositoryRegistry < Gitlab::Database::Migration[2.3]
  disable_ddl_transaction!

  milestone '19.3'

  TABLE = :project_repository_registry
  INDEX = 'index_project_repository_registry_checksum_mismatch'

  def up
    add_concurrent_index TABLE, :verification_retry_at, where: 'checksum_mismatch = true', name: INDEX
  end

  def down
    remove_concurrent_index_by_name TABLE, INDEX
  end
end
