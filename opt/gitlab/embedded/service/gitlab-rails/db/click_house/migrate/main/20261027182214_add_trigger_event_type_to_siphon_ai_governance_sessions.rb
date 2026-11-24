# frozen_string_literal: true

class AddTriggerEventTypeToSiphonAiGovernanceSessions < ClickHouse::Migration
  def up
    execute <<~SQL
      ALTER TABLE siphon_ai_governance_sessions
        ADD COLUMN IF NOT EXISTS trigger_event_type Nullable(Int16)
    SQL
  end

  def down
    execute <<~SQL
      ALTER TABLE siphon_ai_governance_sessions
        DROP COLUMN IF EXISTS trigger_event_type
    SQL
  end
end
