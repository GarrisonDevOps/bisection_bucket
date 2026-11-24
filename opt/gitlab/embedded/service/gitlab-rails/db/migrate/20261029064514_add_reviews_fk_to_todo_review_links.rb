# frozen_string_literal: true

class AddReviewsFkToTodoReviewLinks < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  def up
    add_concurrent_foreign_key :todo_review_links, :reviews, column: :review_id, on_delete: :cascade
  end

  def down
    with_lock_retries do
      remove_foreign_key_if_exists :todo_review_links, column: :review_id
    end
  end
end
