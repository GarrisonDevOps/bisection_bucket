# frozen_string_literal: true

class AddCoveringIndexOnPDuoWorkflowsCheckpointHeaders < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::PartitioningMigrationHelpers

  disable_ddl_transaction!
  milestone '19.6'

  TABLE_NAME = :p_duo_workflows_checkpoint_headers
  COLUMNS = %i[workflow_id thread_ts id].freeze
  INCLUDE_COLUMNS = %i[workflow_created_at parent_ts current_thread].freeze
  INDEX_NAME = 'idx_duo_wf_checkpoint_headers_on_wf_id_thread_ts_id_covering'

  def up
    add_concurrent_partitioned_index(TABLE_NAME, COLUMNS, name: INDEX_NAME, include: INCLUDE_COLUMNS)
  end

  def down
    remove_concurrent_partitioned_index_by_name(TABLE_NAME, INDEX_NAME)
  end
end
