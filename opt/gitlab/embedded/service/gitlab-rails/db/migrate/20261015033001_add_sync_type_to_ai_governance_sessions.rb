# frozen_string_literal: true

class AddSyncTypeToAiGovernanceSessions < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :ai_governance_sessions, :sync_type, :smallint
  end
end
