# frozen_string_literal: true

class AddShareWithGroupLockNotNullConstraintToNamespaces < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  def up
    add_not_null_constraint :namespaces, :share_with_group_lock, validate: false
  end

  def down
    remove_not_null_constraint :namespaces, :share_with_group_lock
  end
end
