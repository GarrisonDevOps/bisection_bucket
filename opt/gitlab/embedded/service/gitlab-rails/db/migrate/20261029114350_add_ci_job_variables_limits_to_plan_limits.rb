# frozen_string_literal: true

class AddCiJobVariablesLimitsToPlanLimits < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :plan_limits, :ci_job_variables_count, :integer, default: 0, null: false
  end
end
