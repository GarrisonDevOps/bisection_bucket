# frozen_string_literal: true

class AddTriageCoveredIndexToSecurityInventoryFilters < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!
  milestone '19.6'

  TABLE_NAME = :security_inventory_filters
  INDEX_NAME = 'idx_sec_inv_filters_traversal_proj_triage_covered'

  def up
    add_concurrent_index(
      TABLE_NAME,
      %i[traversal_ids project_id],
      name: INDEX_NAME,
      include: %i[triage_capabilities_on triage_capabilities_auto],
      where: 'NOT archived AND triage_capabilities_on <> 0'
    )
  end

  def down
    remove_concurrent_index_by_name(TABLE_NAME, INDEX_NAME)
  end
end
