# frozen_string_literal: true

class AddIndexToBulkImportEntitiesOnBulkImportIdAndId < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!

  milestone '19.6'

  TABLE_NAME = :bulk_import_entities
  INDEX_NAME = 'index_bulk_import_entities_on_bulk_import_id_and_id'

  def up
    add_concurrent_index TABLE_NAME, %i[bulk_import_id id], name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name TABLE_NAME, INDEX_NAME
  end
end
