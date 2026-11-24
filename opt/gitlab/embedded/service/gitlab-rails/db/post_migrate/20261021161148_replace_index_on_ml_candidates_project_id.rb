# frozen_string_literal: true

class ReplaceIndexOnMlCandidatesProjectId < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  INDEX_NAME = 'index_ml_candidates_on_project_id_and_eid'
  OLD_INDEX_NAME = 'index_ml_candidates_on_project_id'

  def up
    add_concurrent_index :ml_candidates, [:project_id, :eid], name: INDEX_NAME
    remove_concurrent_index_by_name :ml_candidates, OLD_INDEX_NAME
  end

  # Tested reversibility with db:migrate:down and db:migrate:up, and checked the
  # ml_candidates indexes after each step.
  def down
    add_concurrent_index :ml_candidates, :project_id, name: OLD_INDEX_NAME
    remove_concurrent_index_by_name :ml_candidates, INDEX_NAME
  end
end
