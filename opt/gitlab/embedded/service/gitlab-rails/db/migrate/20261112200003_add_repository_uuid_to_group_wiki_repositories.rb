# frozen_string_literal: true

class AddRepositoryUuidToGroupWikiRepositories < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :group_wiki_repositories, :repository_uuid, :uuid
  end
end
