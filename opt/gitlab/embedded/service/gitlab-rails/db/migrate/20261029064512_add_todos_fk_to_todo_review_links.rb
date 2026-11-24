# frozen_string_literal: true

class AddTodosFkToTodoReviewLinks < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  def up
    add_concurrent_foreign_key :todo_review_links, :todos, column: :todo_id, on_delete: :cascade
  end

  def down
    with_lock_retries do
      remove_foreign_key_if_exists :todo_review_links, column: :todo_id
    end
  end
end
