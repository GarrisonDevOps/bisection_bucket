# frozen_string_literal: true

class AddOrganizationHooksToPlanLimits < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :plan_limits, :organization_hooks, :integer, default: 50, null: false
  end
end
