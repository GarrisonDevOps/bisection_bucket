# frozen_string_literal: true

class AddMetadataVersionToPackagesNpmMetadataCaches < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :packages_npm_metadata_caches, :metadata_version, :smallint, default: 1, null: false
  end
end
