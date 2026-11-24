# frozen_string_literal: true

class RemoveIndexOnWorkflowIdThreadTsIdFromPDuoWorkflowsCheckpointHeaders < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::PartitioningMigrationHelpers

  disable_ddl_transaction!
  milestone '19.6'

  TABLE_NAME = :p_duo_workflows_checkpoint_headers
  COLUMNS = %i[workflow_id thread_ts id].freeze
  INDEX_NAME = 'index_duo_wf_checkpoint_headers_on_workflow_id_thread_ts_id'

  def up
    remove_concurrent_partitioned_index_by_name(TABLE_NAME, INDEX_NAME)
  end

  def down
    add_concurrent_partitioned_index(TABLE_NAME, COLUMNS, name: INDEX_NAME)
  end
end
