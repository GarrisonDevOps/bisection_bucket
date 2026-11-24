# frozen_string_literal: true

class RenameTmpIndexOnSbomOccurrenceRefs < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  OLD_INDEX_NAME = 'tmp_idx_sbom_occurrence_refs_on_project_id_id'
  NEW_INDEX_NAME = 'index_sbom_occurrence_refs_on_project_id_and_id'

  def up
    rename_index :sbom_occurrence_refs, OLD_INDEX_NAME, NEW_INDEX_NAME
  end

  def down
    rename_index :sbom_occurrence_refs, NEW_INDEX_NAME, OLD_INDEX_NAME
  end
end
