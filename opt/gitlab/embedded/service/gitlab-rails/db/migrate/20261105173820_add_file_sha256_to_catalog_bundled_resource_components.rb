# frozen_string_literal: true

class AddFileSha256ToCatalogBundledResourceComponents < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  TABLE_NAME = :catalog_bundled_resource_components
  CONSTRAINT_NAME = 'check_83b055c0e5'

  def up
    with_lock_retries do
      add_column TABLE_NAME, :file_sha256, :binary, if_not_exists: true
    end

    add_check_constraint TABLE_NAME, 'octet_length(file_sha256) <= 32', CONSTRAINT_NAME
  end

  def down
    with_lock_retries do
      remove_column TABLE_NAME, :file_sha256, if_exists: true
    end
  end
end
