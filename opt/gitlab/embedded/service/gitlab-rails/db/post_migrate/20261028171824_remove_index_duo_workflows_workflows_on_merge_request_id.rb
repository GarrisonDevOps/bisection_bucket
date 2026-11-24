# frozen_string_literal: true

class RemoveIndexDuoWorkflowsWorkflowsOnMergeRequestId < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  INDEX_NAME = 'index_duo_workflows_workflows_on_merge_request_id'

  def up
    remove_concurrent_index_by_name :duo_workflows_workflows, INDEX_NAME
  end

  def down
    add_concurrent_index :duo_workflows_workflows, :merge_request_id, name: INDEX_NAME
  end
end
