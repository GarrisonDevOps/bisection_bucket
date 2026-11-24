# frozen_string_literal: true

class AddIndexZoektIndicesOnNodeIdIncludeReservedBytes < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  TABLE_NAME = :zoekt_indices
  INDEX_NAME = 'index_zoekt_indices_on_zoekt_node_id_include_reserved_bytes'

  def up
    add_concurrent_index TABLE_NAME, :zoekt_node_id, include: :reserved_storage_bytes, name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name TABLE_NAME, INDEX_NAME
  end
end
