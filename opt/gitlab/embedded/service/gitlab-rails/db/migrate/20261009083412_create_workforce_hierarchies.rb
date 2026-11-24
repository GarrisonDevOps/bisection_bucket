# frozen_string_literal: true

class CreateWorkforceHierarchies < Gitlab::Database::Migration[2.3]
  milestone '19.6'

  SHARDING_KEY_CONSTRAINT = 'check_workforce_hierarchies_sharding_key'

  def change
    create_table :workforce_hierarchies do |t|
      # Nullable until the Workday integration exists. Made NOT NULL by
      # https://gitlab.com/gitlab-org/gitlab/-/work_items/629838
      t.references :integration, null: true, index: { unique: true }, foreign_key: false
      t.references :group, null: true, index: { unique: true }, foreign_key: false
      t.references :organization, null: true, index: { unique: true }, foreign_key: false
      t.datetime_with_timezone :last_successful_sync_at
      t.timestamps_with_timezone null: false
      t.integer :last_sync_status, limit: 2, null: false, default: 0
      t.integer :last_sync_failure_reason, limit: 2

      t.check_constraint 'num_nonnulls(group_id, organization_id) = 1', name: SHARDING_KEY_CONSTRAINT
    end
  end
end
