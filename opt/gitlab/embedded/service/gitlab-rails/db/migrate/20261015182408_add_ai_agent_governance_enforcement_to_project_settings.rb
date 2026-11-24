# frozen_string_literal: true

class AddAiAgentGovernanceEnforcementToProjectSettings < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :project_settings, :ai_agent_governance_enforcement, :smallint, default: 0, null: false
  end
end
