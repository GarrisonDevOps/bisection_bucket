# frozen_string_literal: true

class CreateNamespaceAiUserMemories < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def up
    create_table :namespace_ai_user_memories do |t|
      t.references :namespace, null: false, index: false, foreign_key: { on_delete: :cascade }
      # FK to users added in post-deploy AddForeignKeyBetweenNamespaceAiUserMemoriesAndUsers
      t.references :user, null: false, index: true
      t.timestamps_with_timezone null: false
      t.text :content, null: false, limit: 4000
    end

    add_index :namespace_ai_user_memories, [:namespace_id, :user_id], unique: true
  end

  def down
    drop_table :namespace_ai_user_memories
  end
end
