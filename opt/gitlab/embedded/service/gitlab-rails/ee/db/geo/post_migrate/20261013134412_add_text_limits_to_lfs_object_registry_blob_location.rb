# frozen_string_literal: true

class AddTextLimitsToLfsObjectRegistryBlobLocation < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  def up
    add_text_limit :lfs_object_registry, :blob_path, 1024
  end

  def down
    remove_text_limit :lfs_object_registry, :blob_path
  end
end
