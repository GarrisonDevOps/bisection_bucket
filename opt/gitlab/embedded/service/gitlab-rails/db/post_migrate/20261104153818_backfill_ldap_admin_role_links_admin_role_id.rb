# frozen_string_literal: true

# Fills admin_role_id on existing ldap_admin_role_links. The sync trigger
# fills every later write. See https://gitlab.com/groups/gitlab-org/-/epics/17390
class BackfillLdapAdminRoleLinksAdminRoleId < Gitlab::Database::Migration[2.4]
  restrict_gitlab_migration gitlab_schema: :gitlab_main_org

  milestone '19.6'

  # Runs after the admin_roles backfill, so every admin role has its copy.
  def up
    execute(<<~SQL)
      UPDATE ldap_admin_role_links
      SET admin_role_id = ldap_admin_role_links.member_role_id
      FROM admin_roles
      WHERE admin_roles.id = ldap_admin_role_links.member_role_id
        AND ldap_admin_role_links.admin_role_id IS NULL
    SQL
  end

  def down
    # no-op, the column is kept in sync by the trigger
  end
end
