# frozen_string_literal: true

# Copies existing custom admin roles from member_roles into admin_roles,
# keeping their IDs. The sync trigger copies every later write.
# See https://gitlab.com/groups/gitlab-org/-/epics/17390
class BackfillAdminRolesFromMemberRoles < Gitlab::Database::Migration[2.4]
  restrict_gitlab_migration gitlab_schema: :gitlab_main_org

  milestone '19.6'

  # Same upsert as the trigger, so existing copies end up matching member_roles.
  def up
    execute(<<~SQL)
      INSERT INTO admin_roles (id, name, description, permissions, organization_id, created_at, updated_at)
      SELECT id, name, description, permissions, organization_id, created_at, updated_at
      FROM member_roles
      WHERE base_access_level IS NULL AND organization_id IS NOT NULL
      FOR SHARE
      ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        description = EXCLUDED.description,
        permissions = EXCLUDED.permissions,
        organization_id = EXCLUDED.organization_id,
        updated_at = EXCLUDED.updated_at
    SQL
  end

  def down
    # no-op, the copies are kept in sync by the trigger
  end
end
