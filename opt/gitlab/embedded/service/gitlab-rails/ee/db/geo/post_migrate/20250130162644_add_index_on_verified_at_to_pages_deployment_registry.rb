# frozen_string_literal: true

class AddIndexOnVerifiedAtToPagesDeploymentRegistry < Gitlab::Database::Migration[2.2]
  disable_ddl_transaction!

  milestone '17.9'

  TABLE = :pages_deployment_registry
  INDEX = 'index_pages_deployment_registry_on_verified_at'

  def up
    add_concurrent_index TABLE, :verified_at, name: INDEX
  end

  def down
    remove_concurrent_index_by_name TABLE, INDEX
  end
end
