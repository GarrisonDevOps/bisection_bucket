# frozen_string_literal: true

class AddFksToWorkforceHierarchies < Gitlab::Database::Migration[2.3]
  disable_ddl_transaction!

  milestone '19.6'

  def up
    # Deleting the integration removes the tenant's hierarchy data. The integration delete in
    # https://gitlab.com/gitlab-org/gitlab/-/work_items/629842 removes the people in batches first;
    # this cascade is the backstop so no HR data is left behind if the row is removed another way.
    add_concurrent_foreign_key :workforce_hierarchies, :integrations, column: :integration_id, on_delete: :cascade
    add_concurrent_foreign_key :workforce_hierarchies, :namespaces, column: :group_id, on_delete: :cascade
    add_concurrent_foreign_key :workforce_hierarchies, :organizations, column: :organization_id, on_delete: :cascade
  end

  def down
    with_lock_retries do
      remove_foreign_key_if_exists :workforce_hierarchies, column: :integration_id
      remove_foreign_key_if_exists :workforce_hierarchies, column: :group_id
      remove_foreign_key_if_exists :workforce_hierarchies, column: :organization_id
    end
  end
end
