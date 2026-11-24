# frozen_string_literal: true

class AddMcpRunningIndexToAiGovernanceSessions < Gitlab::Database::Migration[2.3]
  milestone '19.6'
  disable_ddl_transaction!

  INDEX_NAME = 'index_ai_governance_sessions_on_started_at_mcp_running'
  # source: mcp (3), status: running (1) - the only rows
  # Mcp::Audit::CloseIdleSessionsService sweeps, so the index stays small even as
  # the table grows across every AI session source.
  CONDITION = 'source = 3 AND status = 1'

  def up
    add_concurrent_index :ai_governance_sessions, :session_started_at, where: CONDITION, name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name :ai_governance_sessions, INDEX_NAME
  end
end
