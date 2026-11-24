# frozen_string_literal: true

class AddRepositoryUuidToDesignManagementRepositories < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :design_management_repositories, :repository_uuid, :uuid
  end
end
