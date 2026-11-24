# frozen_string_literal: true

class AddSyncTypeToSiphonAiGovernanceSessions < ClickHouse::Migration
  def up
    execute <<~SQL
      ALTER TABLE siphon_ai_governance_sessions
        ADD COLUMN IF NOT EXISTS sync_type Nullable(Int16)
    SQL
  end

  def down
    execute <<~SQL
      ALTER TABLE siphon_ai_governance_sessions
        DROP COLUMN IF EXISTS sync_type
    SQL
  end
end
