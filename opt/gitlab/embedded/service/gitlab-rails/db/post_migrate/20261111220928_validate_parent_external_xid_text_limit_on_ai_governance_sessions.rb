# frozen_string_literal: true

class ValidateParentExternalXidTextLimitOnAiGovernanceSessions < Gitlab::Database::Migration[2.4]
  milestone '19.7'

  disable_ddl_transaction!

  def up
    validate_text_limit :ai_governance_sessions, :parent_external_xid
  end

  def down
    # no-op
  end
end
