# frozen_string_literal: true

# Copies member_role_id into admin_role_id on ldap_admin_role_links.
# See https://gitlab.com/groups/gitlab-org/-/epics/17390
class CreateTriggerToSyncLdapAdminRoleLinksAdminRoleId < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::SchemaHelpers

  milestone '19.6'

  TRIGGER_NAME = 'trigger_sync_ldap_admin_role_links_admin_role_id'
  FUNCTION_NAME = 'sync_ldap_admin_role_links_admin_role_id'

  # Roles without an admin_roles row yet are left NULL here and filled by the backfill.
  # Skips rows without member_role_id so admin_role_id written by the app is kept.
  FUNCTION_BODY = <<~SQL
    IF NEW.member_role_id IS NOT NULL THEN
      NEW.admin_role_id := (SELECT id FROM admin_roles WHERE id = NEW.member_role_id);
    END IF;

    RETURN NEW;
  SQL

  def up
    create_trigger_function(FUNCTION_NAME) { FUNCTION_BODY }
    create_trigger(:ldap_admin_role_links, TRIGGER_NAME, FUNCTION_NAME,
      fires: 'BEFORE INSERT OR UPDATE OF member_role_id')
  end

  def down
    drop_trigger(:ldap_admin_role_links, TRIGGER_NAME)
    drop_function(FUNCTION_NAME)
  end
end
