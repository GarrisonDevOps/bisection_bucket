# frozen_string_literal: true

class AddIntegrationExecutionsToPlanLimits < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :plan_limits, :integration_executions, :integer, default: 0, null: false
    add_column :plan_limits, :integration_executions_datadog, :integer, default: 0, null: false
  end
end
