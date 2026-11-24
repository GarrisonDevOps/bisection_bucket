# frozen_string_literal: true

class AddIndexOnZoektIndicesNodeIdLastIndexedAt < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  INDEX_NAME = 'index_zoekt_indices_on_zoekt_node_id_and_last_indexed_at'

  def up
    add_concurrent_index :zoekt_indices, [:zoekt_node_id, :last_indexed_at], name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name :zoekt_indices, INDEX_NAME
  end
end
