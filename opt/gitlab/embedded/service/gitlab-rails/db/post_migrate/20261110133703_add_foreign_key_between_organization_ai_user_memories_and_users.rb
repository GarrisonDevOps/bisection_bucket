# frozen_string_literal: true

class AddForeignKeyBetweenOrganizationAiUserMemoriesAndUsers < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  def up
    add_concurrent_foreign_key :organization_ai_user_memories, :users, # rubocop:disable Migration/ForeignKeysToDestroyServiceTables -- handles_removal_of declared in Users::DestroyService
      column: :user_id, on_delete: :cascade
  end

  def down
    with_lock_retries do
      remove_foreign_key_if_exists :organization_ai_user_memories, column: :user_id
    end
  end
end
