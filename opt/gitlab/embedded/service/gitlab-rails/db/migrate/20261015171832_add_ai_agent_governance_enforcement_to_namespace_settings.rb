# frozen_string_literal: true

class AddAiAgentGovernanceEnforcementToNamespaceSettings < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :namespace_settings, :ai_agent_governance_enforcement, :smallint
    add_column :namespace_settings, :lock_ai_agent_governance_enforcement, :boolean, default: false, null: false
  end
end
