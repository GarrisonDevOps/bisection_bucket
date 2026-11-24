# frozen_string_literal: true

class CreateTodoReviewLinks < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    create_table :todo_review_links, id: false do |t|
      t.bigint :todo_id, primary_key: true, default: nil
      t.bigint :project_id, null: false
      t.bigint :review_id, null: false

      t.index :project_id
      t.index :review_id
    end
  end
end
