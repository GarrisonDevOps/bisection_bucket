# frozen_string_literal: true

class RemoveTmpIndexAiCatalogItemConsumersOnItemIdAndId < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!

  milestone '19.6'

  INDEX_NAME = 'tmp_idx_ai_catalog_item_consumers_on_item_id_and_id'

  def up
    remove_concurrent_index_by_name :ai_catalog_item_consumers, INDEX_NAME
  end

  def down
    add_concurrent_index :ai_catalog_item_consumers, [:ai_catalog_item_id, :id], name: INDEX_NAME
  end
end
