# frozen_string_literal: true

class AddUniqueIndexToPackageFileRegistry < Gitlab::Database::Migration[2.3]
  disable_ddl_transaction!

  milestone '19.5'

  TABLE_NAME = :package_file_registry
  OLD_INDEX_NAME = 'index_package_file_registry_on_repository_id'
  UNIQUE_INDEX_NAME = 'index_package_file_registry_on_package_file_id_unique'

  def up
    add_concurrent_index TABLE_NAME, :package_file_id, name: UNIQUE_INDEX_NAME, unique: true
    remove_concurrent_index_by_name TABLE_NAME, OLD_INDEX_NAME
  end

  def down
    add_concurrent_index TABLE_NAME, :package_file_id, name: OLD_INDEX_NAME
    remove_concurrent_index_by_name TABLE_NAME, UNIQUE_INDEX_NAME
  end
end
