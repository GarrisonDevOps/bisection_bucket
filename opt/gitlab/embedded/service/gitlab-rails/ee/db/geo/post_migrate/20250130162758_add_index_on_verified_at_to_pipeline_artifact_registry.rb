# frozen_string_literal: true

class AddIndexOnVerifiedAtToPipelineArtifactRegistry < Gitlab::Database::Migration[2.2]
  disable_ddl_transaction!

  milestone '17.9'

  TABLE = :pipeline_artifact_registry
  INDEX = 'index_pipeline_artifact_registry_on_verified_at'

  def up
    add_concurrent_index TABLE, :verified_at, name: INDEX
  end

  def down
    remove_concurrent_index_by_name TABLE, INDEX
  end
end
