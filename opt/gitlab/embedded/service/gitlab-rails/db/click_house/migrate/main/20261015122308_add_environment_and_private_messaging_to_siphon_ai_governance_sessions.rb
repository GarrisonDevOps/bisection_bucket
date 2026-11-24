# frozen_string_literal: true

class AddEnvironmentAndPrivateMessagingToSiphonAiGovernanceSessions < ClickHouse::Migration
  def up
    execute <<~SQL
      ALTER TABLE siphon_ai_governance_sessions
        ADD COLUMN IF NOT EXISTS environment Nullable(Int16),
        ADD COLUMN IF NOT EXISTS private_messaging Bool DEFAULT false
    SQL
  end

  def down
    execute <<~SQL
      ALTER TABLE siphon_ai_governance_sessions
        DROP COLUMN IF EXISTS environment,
        DROP COLUMN IF EXISTS private_messaging
    SQL
  end
end
