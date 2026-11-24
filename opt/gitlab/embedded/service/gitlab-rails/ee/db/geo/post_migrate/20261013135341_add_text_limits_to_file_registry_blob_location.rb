# frozen_string_literal: true

class AddTextLimitsToFileRegistryBlobLocation < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  def up
    add_text_limit :file_registry, :blob_path, 1024
    add_text_limit :file_registry, :uploader_class, 255
  end

  def down
    remove_text_limit :file_registry, :blob_path
    remove_text_limit :file_registry, :uploader_class
  end
end
