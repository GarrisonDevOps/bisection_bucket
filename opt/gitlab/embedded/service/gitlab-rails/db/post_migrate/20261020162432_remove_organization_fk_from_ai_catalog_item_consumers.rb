# frozen_string_literal: true

class RemoveOrganizationFkFromAiCatalogItemConsumers < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  FK_NAME = :fk_9e3abe6238

  def up
    with_lock_retries do
      remove_foreign_key_if_exists :ai_catalog_item_consumers, :organizations,
        column: :organization_id, name: FK_NAME
    end
  end

  def down
    add_concurrent_foreign_key :ai_catalog_item_consumers, :organizations,
      column: :organization_id, name: FK_NAME, on_delete: :cascade
  end
end
