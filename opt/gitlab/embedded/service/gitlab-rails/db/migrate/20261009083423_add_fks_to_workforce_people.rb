# frozen_string_literal: true

class AddFksToWorkforcePeople < Gitlab::Database::Migration[2.3]
  disable_ddl_transaction!

  milestone '19.6'

  def up
    add_concurrent_foreign_key :workforce_people, :workforce_hierarchies,
      column: :workforce_hierarchy_id, on_delete: :cascade
    # A person outlives the GitLab user they were matched to; the next sync re-matches or leaves them unmatched.
    # rubocop:disable Migration/ForeignKeysToDestroyServiceTables -- Users::DestroyService declares handles_removal_of :workforce_people
    add_concurrent_foreign_key :workforce_people, :users, column: :user_id, on_delete: :nullify
    # rubocop:enable Migration/ForeignKeysToDestroyServiceTables
    add_concurrent_foreign_key :workforce_people, :namespaces, column: :group_id, on_delete: :cascade
    add_concurrent_foreign_key :workforce_people, :organizations, column: :organization_id, on_delete: :cascade
  end

  def down
    with_lock_retries do
      remove_foreign_key_if_exists :workforce_people, column: :workforce_hierarchy_id
      remove_foreign_key_if_exists :workforce_people, column: :user_id
      remove_foreign_key_if_exists :workforce_people, column: :group_id
      remove_foreign_key_if_exists :workforce_people, column: :organization_id
    end
  end
end
