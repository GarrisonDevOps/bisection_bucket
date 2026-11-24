# frozen_string_literal: true

class AddIndexOnVerifiedAtToMergeRequestDiffRegistry < Gitlab::Database::Migration[2.2]
  disable_ddl_transaction!

  milestone '17.9'

  TABLE = :merge_request_diff_registry
  INDEX = 'index_merge_request_diff_registry_on_verified_at'

  def up
    add_concurrent_index TABLE, :verified_at, name: INDEX
  end

  def down
    remove_concurrent_index_by_name TABLE, INDEX
  end
end
