# frozen_string_literal: true

# Copies existing custom admin role assignments from user_member_roles into
# user_admin_roles. The sync trigger copies every later write.
# See https://gitlab.com/groups/gitlab-org/-/epics/17390
class BackfillUserAdminRolesFromUserMemberRoles < Gitlab::Database::Migration[2.4]
  restrict_gitlab_migration gitlab_schema: :gitlab_main_user

  milestone '19.6'

  # Runs after the admin_roles backfill, so every admin role has its copy.
  def up
    execute(<<~SQL)
      INSERT INTO user_admin_roles (user_id, admin_role_id, ldap, created_at, updated_at)
      SELECT user_member_roles.user_id, user_member_roles.member_role_id, user_member_roles.ldap,
        user_member_roles.created_at, user_member_roles.updated_at
      FROM user_member_roles
      INNER JOIN member_roles ON member_roles.id = user_member_roles.member_role_id
      WHERE member_roles.base_access_level IS NULL AND member_roles.organization_id IS NOT NULL
      FOR SHARE
      ON CONFLICT (user_id) DO UPDATE SET
        admin_role_id = EXCLUDED.admin_role_id,
        ldap = EXCLUDED.ldap,
        created_at = EXCLUDED.created_at,
        updated_at = EXCLUDED.updated_at
    SQL
  end

  def down
    # no-op, the copies are kept in sync by the trigger
  end
end
