# frozen_string_literal: true

class AddIndexOnJobArtifactRegistry < Gitlab::Database::Migration[2.2]
  milestone '17.5'

  disable_ddl_transaction!

  TABLE = :job_artifact_registry
  INDEX_STATE = 'index_job_artifact_registry_state'

  def up
    add_concurrent_index TABLE, :state, name: INDEX_STATE
  end

  def down
    remove_concurrent_index_by_name TABLE, INDEX_STATE
  end
end
