# frozen_string_literal: true

class AddProjectRepositoryIdToProjectRepositoryRegistry < Gitlab::Database::Migration[2.3]
  milestone '18.4'

  disable_ddl_transaction!

  def up
    add_column :project_repository_registry, :project_repository_id, :bigint

    # Add index on new column (not unique initially since data will be populated gradually)
    add_concurrent_index :project_repository_registry, :project_repository_id,
      name: 'index_project_repository_registry_on_project_repository_id'

    # Note: Data population will be handled by the application code when records are accessed.
    # This avoids cross-database query issues during migration.
  end

  def down
    remove_concurrent_index :project_repository_registry, :project_repository_id,
      name: 'index_project_repository_registry_on_project_repository_id'
    remove_column :project_repository_registry, :project_repository_id
  end
end
