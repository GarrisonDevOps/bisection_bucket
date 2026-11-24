# frozen_string_literal: true

class RemoveIndexMergeRequestReviewersOnUserId < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  INDEX_NAME = 'index_merge_request_reviewers_on_user_id'

  def up
    remove_concurrent_index_by_name :merge_request_reviewers, INDEX_NAME
  end

  def down
    add_concurrent_index :merge_request_reviewers, :user_id, name: INDEX_NAME
  end
end
