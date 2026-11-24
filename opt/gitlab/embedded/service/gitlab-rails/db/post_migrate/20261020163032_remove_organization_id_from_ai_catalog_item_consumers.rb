# frozen_string_literal: true

class RemoveOrganizationIdFromAiCatalogItemConsumers < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  INDEX_NAME = :index_ai_catalog_item_consumers_on_organization_id

  def up
    with_lock_retries do
      remove_column :ai_catalog_item_consumers, :organization_id, if_exists: true
    end
  end

  def down
    add_column :ai_catalog_item_consumers, :organization_id, :bigint, if_not_exists: true
    add_concurrent_index :ai_catalog_item_consumers, :organization_id, name: INDEX_NAME
  end
end
