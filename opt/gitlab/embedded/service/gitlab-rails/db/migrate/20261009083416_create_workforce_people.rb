# frozen_string_literal: true

class CreateWorkforcePeople < Gitlab::Database::Migration[2.3]
  milestone '19.6'

  SHARDING_KEY_CONSTRAINT = 'check_workforce_people_sharding_key'
  EXTERNAL_XID_INDEX = 'index_workforce_people_on_hierarchy_id_and_external_xid'
  USER_INDEX = 'index_workforce_people_on_hierarchy_id_and_user_id'
  MANAGER_INDEX = 'index_workforce_people_on_hierarchy_id_and_manager_xid'
  TRAVERSAL_INDEX = 'index_workforce_people_on_hierarchy_id_and_traversal_ids'

  def change
    create_table :workforce_people do |t|
      # Every index below leads with workforce_hierarchy_id, so it also serves the foreign key.
      t.references :workforce_hierarchy, null: false, index: false, foreign_key: false
      t.references :user, null: true, index: true, foreign_key: false
      t.references :group, null: true, index: true, foreign_key: false
      t.references :organization, null: true, index: true, foreign_key: false
      t.timestamps_with_timezone null: false
      t.bigint :traversal_ids, array: true, null: false, default: []
      t.text :external_xid, null: false, limit: 255
      t.text :manager_external_xid, limit: 255
      t.text :full_name, null: false, limit: 255

      t.index [:workforce_hierarchy_id, :external_xid], unique: true, name: EXTERNAL_XID_INDEX
      # Enforces one person per matched user per tenant, and serves the reverse lookup.
      t.index [:workforce_hierarchy_id, :user_id], unique: true, where: 'user_id IS NOT NULL', name: USER_INDEX
      t.index [:workforce_hierarchy_id, :manager_external_xid], name: MANAGER_INDEX
      # Btree, not GIN: the subtree read is a half-open range scan over traversal_ids,
      # the same technique as index_namespaces_on_traversal_ids_for_groups_btree.
      t.index [:workforce_hierarchy_id, :traversal_ids], name: TRAVERSAL_INDEX

      t.check_constraint 'num_nonnulls(group_id, organization_id) = 1', name: SHARDING_KEY_CONSTRAINT
    end
  end
end
