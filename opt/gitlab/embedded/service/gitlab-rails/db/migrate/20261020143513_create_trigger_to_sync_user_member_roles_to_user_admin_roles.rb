# frozen_string_literal: true

# Copies custom admin role assignments from user_member_roles into
# user_admin_roles. See https://gitlab.com/groups/gitlab-org/-/epics/17390
class CreateTriggerToSyncUserMemberRolesToUserAdminRoles < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::SchemaHelpers

  milestone '19.6'

  TRIGGER_NAME = 'trigger_sync_user_member_roles_to_user_admin_roles'
  FUNCTION_NAME = 'sync_user_member_roles_to_user_admin_roles'

  # Roles created before the member_roles trigger have no admin_roles row
  # until the backfill runs, so their assignments are skipped here and copied there.
  FUNCTION_BODY = <<~SQL
    IF (TG_OP = 'UPDATE' OR TG_OP = 'DELETE') THEN
      DELETE FROM user_admin_roles WHERE user_id = OLD.user_id AND admin_role_id = OLD.member_role_id;
    END IF;

    IF (TG_OP = 'INSERT' OR TG_OP = 'UPDATE') THEN
      INSERT INTO user_admin_roles (user_id, admin_role_id, ldap, created_at, updated_at)
      SELECT NEW.user_id, NEW.member_role_id, NEW.ldap, NEW.created_at, NEW.updated_at
      WHERE EXISTS (SELECT 1 FROM admin_roles WHERE id = NEW.member_role_id)
      ON CONFLICT (user_id) DO UPDATE SET
        admin_role_id = EXCLUDED.admin_role_id,
        ldap = EXCLUDED.ldap,
        created_at = EXCLUDED.created_at,
        updated_at = EXCLUDED.updated_at;
      RETURN NEW;
    END IF;

    RETURN OLD;
  SQL

  def up
    create_trigger_function(FUNCTION_NAME) { FUNCTION_BODY }
    create_trigger(:user_member_roles, TRIGGER_NAME, FUNCTION_NAME, fires: 'AFTER INSERT OR UPDATE OR DELETE')
  end

  def down
    drop_trigger(:user_member_roles, TRIGGER_NAME)
    drop_function(FUNCTION_NAME)
  end
end
