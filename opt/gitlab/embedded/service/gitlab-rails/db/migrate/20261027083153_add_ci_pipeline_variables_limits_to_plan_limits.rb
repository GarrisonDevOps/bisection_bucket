# frozen_string_literal: true

class AddCiPipelineVariablesLimitsToPlanLimits < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :plan_limits, :ci_pipeline_variables_count, :integer, default: 0, null: false
    add_column :plan_limits, :ci_variable_value_size, :integer, default: 0, null: false
    add_column :plan_limits, :ci_variable_file_value_size, :integer, default: 0, null: false
  end
end
