# frozen_string_literal: true

class AddRepositoryUuidToSnippetRepositories < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :snippet_repositories, :repository_uuid, :uuid
  end
end
