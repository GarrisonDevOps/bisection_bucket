# frozen_string_literal: true

class AddParentExternalXidToSiphonAiGovernanceSessions < ClickHouse::Migration
  def up
    execute <<~SQL
      ALTER TABLE siphon_ai_governance_sessions
        ADD COLUMN IF NOT EXISTS parent_external_xid Nullable(String)
    SQL
  end

  def down
    execute <<~SQL
      ALTER TABLE siphon_ai_governance_sessions
        DROP COLUMN IF EXISTS parent_external_xid
    SQL
  end
end
