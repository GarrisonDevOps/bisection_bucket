# frozen_string_literal: true

class RemoveProjectIdIndexFromSbomOccurrenceRefs < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!

  milestone '19.6'

  INDEX_NAME = 'index_sbom_occurrence_refs_on_project_id'

  def up
    remove_concurrent_index_by_name :sbom_occurrence_refs, INDEX_NAME
  end

  def down
    add_concurrent_index :sbom_occurrence_refs, :project_id, name: INDEX_NAME
  end
end
