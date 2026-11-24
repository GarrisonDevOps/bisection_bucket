# frozen_string_literal: true

class AddParentExternalXidToAiGovernanceSessions < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!
  milestone '19.7'

  def up
    with_lock_retries do
      add_column :ai_governance_sessions, :parent_external_xid, :text, if_not_exists: true
    end

    # Validated in a post-deployment migration.
    add_text_limit :ai_governance_sessions, :parent_external_xid, 255, validate: false
  end

  def down
    with_lock_retries do
      remove_column :ai_governance_sessions, :parent_external_xid, if_exists: true
    end
  end
end
