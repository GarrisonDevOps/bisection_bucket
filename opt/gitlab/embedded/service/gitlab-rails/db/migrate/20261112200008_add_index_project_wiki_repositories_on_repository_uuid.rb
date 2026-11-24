# frozen_string_literal: true

class AddIndexProjectWikiRepositoriesOnRepositoryUuid < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  INDEX_NAME = 'index_project_wiki_repositories_on_repository_uuid'

  def up
    add_concurrent_index :project_wiki_repositories, :repository_uuid,
      unique: true, where: 'repository_uuid IS NOT NULL', name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name :project_wiki_repositories, INDEX_NAME
  end
end
