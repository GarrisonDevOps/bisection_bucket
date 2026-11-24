# frozen_string_literal: true

# Every LDAP link needs a role in member_roles, admin_roles or both.
# The table is small, so the constraint is validated here.
class AddRoleNotNullConstraintToLdapAdminRoleLinks < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  def up
    add_multi_column_not_null_constraint(:ldap_admin_role_links, :member_role_id, :admin_role_id, operator: '>=')
  end

  def down
    remove_multi_column_not_null_constraint(:ldap_admin_role_links, :member_role_id, :admin_role_id)
  end
end
