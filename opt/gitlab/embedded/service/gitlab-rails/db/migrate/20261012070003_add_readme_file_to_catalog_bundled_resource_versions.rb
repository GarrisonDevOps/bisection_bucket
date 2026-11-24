# frozen_string_literal: true

class AddReadmeFileToCatalogBundledResourceVersions < Gitlab::Database::Migration[2.3]
  milestone '19.6'

  disable_ddl_transaction!

  TABLE = :catalog_bundled_resource_versions

  def up
    add_column TABLE, :readme_file, :text, if_not_exists: true
    add_column TABLE, :readme_file_store, :smallint, default: 1, null: false, if_not_exists: true

    add_text_limit TABLE, :readme_file, 255
  end

  def down
    remove_column TABLE, :readme_file, if_exists: true
    remove_column TABLE, :readme_file_store, if_exists: true
  end
end
