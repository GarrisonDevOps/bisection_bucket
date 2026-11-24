# frozen_string_literal: true

class RemoveSnippetRepositoryRegistryForceToRedownloadColumn < Gitlab::Database::Migration[2.2]
  milestone '16.10'

  def up
    remove_column :snippet_repository_registry, :force_to_redownload, if_exists: true
  end

  def down
    add_column :snippet_repository_registry,
      :force_to_redownload,
      :boolean,
      if_not_exists: true
  end
end
