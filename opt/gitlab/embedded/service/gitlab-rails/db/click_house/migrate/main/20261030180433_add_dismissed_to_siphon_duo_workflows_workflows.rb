# frozen_string_literal: true

class AddDismissedToSiphonDuoWorkflowsWorkflows < ClickHouse::Migration
  def up
    execute <<~SQL
      ALTER TABLE siphon_duo_workflows_workflows ADD COLUMN IF NOT EXISTS dismissed Bool DEFAULT false;
    SQL
  end

  def down
    execute <<~SQL
      ALTER TABLE siphon_duo_workflows_workflows DROP COLUMN IF EXISTS dismissed;
    SQL
  end
end
