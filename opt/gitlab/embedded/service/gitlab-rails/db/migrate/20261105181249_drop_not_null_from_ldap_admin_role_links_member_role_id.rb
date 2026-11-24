# frozen_string_literal: true

# Lets LDAP links point only at admin_roles once roles are created there.
# See https://gitlab.com/groups/gitlab-org/-/epics/17390
class DropNotNullFromLdapAdminRoleLinksMemberRoleId < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def up
    change_column_null :ldap_admin_role_links, :member_role_id, true
  end

  # Only works while every link still has a member_role_id. Once the flag creates
  # admin-only links, those rows need removing before this can roll back.
  def down
    change_column_null :ldap_admin_role_links, :member_role_id, false
  end
end
