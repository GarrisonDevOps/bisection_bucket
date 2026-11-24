# frozen_string_literal: true

class CreateOrganizationAiUserMemories < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def up
    create_table :organization_ai_user_memories do |t|
      t.references :organization, null: false, index: false,
        foreign_key: { to_table: :organizations, on_delete: :cascade }
      # FK to users added in post-deploy AddForeignKeyBetweenOrganizationAiUserMemoriesAndUsers
      t.references :user, null: false, index: true
      t.timestamps_with_timezone null: false
      t.text :content, null: false, limit: 4000
    end

    add_index :organization_ai_user_memories, [:organization_id, :user_id],
      unique: true,
      name: 'idx_org_ai_user_memories_on_org_id_and_user_id'
  end

  def down
    drop_table :organization_ai_user_memories
  end
end
