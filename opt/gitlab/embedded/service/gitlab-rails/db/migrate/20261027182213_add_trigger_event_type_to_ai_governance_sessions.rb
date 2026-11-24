# frozen_string_literal: true

class AddTriggerEventTypeToAiGovernanceSessions < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :ai_governance_sessions, :trigger_event_type, :smallint
  end
end
