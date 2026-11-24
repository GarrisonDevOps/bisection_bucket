# frozen_string_literal: true

class AddDismissedToDuoWorkflowsWorkflows < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :duo_workflows_workflows, :dismissed, :boolean, default: false, null: false
  end
end
