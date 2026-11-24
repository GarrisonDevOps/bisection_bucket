# frozen_string_literal: true

class AddIndexCiResourceGroupsOnProjectIdAndId < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  INDEX_NAME = 'index_ci_resource_groups_on_project_id_and_id'

  def up
    add_concurrent_index :ci_resource_groups, [:project_id, :id], name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name :ci_resource_groups, INDEX_NAME
  end
end
