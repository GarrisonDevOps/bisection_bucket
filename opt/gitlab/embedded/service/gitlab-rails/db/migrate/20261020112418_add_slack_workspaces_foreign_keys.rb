# frozen_string_literal: true

class AddSlackWorkspacesForeignKeys < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!

  milestone '19.6'

  def up
    # Cascade-only delete is intended, see spec/support/database/destroy_service_foreign_keys_todo.yml
    add_concurrent_foreign_key :slack_workspaces, :namespaces, column: :duo_namespace_id, on_delete: :cascade
  end

  def down
    with_lock_retries do
      remove_foreign_key_if_exists :slack_workspaces, column: :duo_namespace_id
    end
  end
end
