# frozen_string_literal: true

class AddIndexDuoWorkflowsWorkflowsOnProjectUpdatedAtId < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  INDEX_NAME = 'index_duo_workflows_workflows_project_updated_at_id'

  def up
    # 2 and 5 are web and ambient, Ai::DuoWorkflows::Workflow::ENVIRONMENTS_FROM_PIPELINE
    add_concurrent_index :duo_workflows_workflows, [:project_id, :updated_at, :id],
      order: { updated_at: :desc, id: :desc },
      where: "environment IN (2, 5) AND workflow_definition <> 'chat'",
      name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name :duo_workflows_workflows, INDEX_NAME
  end
end
