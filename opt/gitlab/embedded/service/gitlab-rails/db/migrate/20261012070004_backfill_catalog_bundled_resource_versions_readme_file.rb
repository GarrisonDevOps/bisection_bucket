# frozen_string_literal: true

class BackfillCatalogBundledResourceVersionsReadmeFile < Gitlab::Database::Migration[2.3]
  milestone '19.6'
  restrict_gitlab_migration gitlab_schema: :gitlab_main_cell_local

  disable_ddl_transaction!

  BATCH_SIZE = 500

  def up
    each_batch_range('catalog_bundled_resource_versions', connection: connection, of: BATCH_SIZE) do |min, max|
      connection.execute(<<~SQL)
        UPDATE catalog_bundled_resource_versions
        SET readme_file = 'readme.json',
            readme_file_store = file_store
        WHERE id BETWEEN #{min} AND #{max}
          AND readme_file IS NULL
      SQL
    end
  end

  def down
    # no-op: the column is nullable and the value is derivable, so nothing is lost.
  end
end
