# frozen_string_literal: true

class RemoveProjectWikiRepositoryRegistryForceToRedownloadColumn < Gitlab::Database::Migration[2.2]
  milestone '16.10'

  def up
    remove_column :project_wiki_repository_registry, :force_to_redownload, if_exists: true
  end

  def down
    add_column :project_wiki_repository_registry,
      :force_to_redownload,
      :boolean,
      default: false,
      null: false,
      if_not_exists: true
  end
end
