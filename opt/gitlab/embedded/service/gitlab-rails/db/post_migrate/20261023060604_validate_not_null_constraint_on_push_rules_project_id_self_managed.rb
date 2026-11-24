# frozen_string_literal: true

class ValidateNotNullConstraintOnPushRulesProjectIdSelfManaged < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  def up
    return if Gitlab.com_except_jh?

    validate_not_null_constraint :push_rules, :project_id
  end

  def down
    # PostgreSQL cannot mark a validated constraint as NOT VALID without recreating it.
  end
end
