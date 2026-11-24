# frozen_string_literal: true

class AddNotNullConstraintToCiRunnersUuid < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!

  milestone '19.6'

  def up
    add_not_null_constraint :ci_runners, :uuid
  end

  def down
    remove_not_null_constraint :ci_runners, :uuid
  end
end
