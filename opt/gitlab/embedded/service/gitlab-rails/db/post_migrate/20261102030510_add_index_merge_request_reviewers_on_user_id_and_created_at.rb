# frozen_string_literal: true

class AddIndexMergeRequestReviewersOnUserIdAndCreatedAt < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  INDEX_NAME = 'index_merge_request_reviewers_on_user_id_and_created_at'

  def up
    add_concurrent_index :merge_request_reviewers, [:user_id, :created_at], name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name :merge_request_reviewers, INDEX_NAME
  end
end
