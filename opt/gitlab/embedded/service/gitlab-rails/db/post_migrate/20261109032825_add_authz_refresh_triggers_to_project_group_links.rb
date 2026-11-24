# frozen_string_literal: true

# Queues a project_authorizations refresh for a project when one of its group
# shares is added, removed or changed, in the same transaction as the write,
# whatever made it.
class AddAuthzRefreshTriggersToProjectGroupLinks < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::SchemaHelpers

  milestone '19.6'

  disable_ddl_transaction!

  TABLE = :project_group_links

  # Authz::ProjectAuthorizations::RefreshEvent.target_types[:project]
  PROJECT = 1

  FUNCTIONS = {
    authz_refresh_on_project_group_links_statement: <<~SQL,
      INSERT INTO authz_refresh_events (target_type, target_id)
      SELECT DISTINCT #{PROJECT}, l.project_id FROM changed_rows l;
      RETURN NULL;
    SQL
    # A share moved to another project changes access on both projects.
    authz_refresh_on_project_group_links_update: <<~SQL
      INSERT INTO authz_refresh_events (target_type, target_id)
      SELECT DISTINCT #{PROJECT}, p.id FROM (VALUES (OLD.project_id), (NEW.project_id)) AS p (id);
      RETURN NULL;
    SQL
  }.freeze

  TRIGGERS = {
    trigger_authz_refresh_on_project_group_links_insert: <<~SQL,
      AFTER INSERT ON project_group_links REFERENCING NEW TABLE AS changed_rows
      FOR EACH STATEMENT EXECUTE FUNCTION authz_refresh_on_project_group_links_statement()
    SQL
    trigger_authz_refresh_on_project_group_links_delete: <<~SQL,
      AFTER DELETE ON project_group_links REFERENCING OLD TABLE AS changed_rows
      FOR EACH STATEMENT EXECUTE FUNCTION authz_refresh_on_project_group_links_statement()
    SQL
    trigger_authz_refresh_on_project_group_links_update: <<~SQL
      AFTER UPDATE ON project_group_links FOR EACH ROW
      WHEN (OLD.project_id IS DISTINCT FROM NEW.project_id OR OLD.group_id IS DISTINCT FROM NEW.group_id
        OR OLD.group_access IS DISTINCT FROM NEW.group_access)
      EXECUTE FUNCTION authz_refresh_on_project_group_links_update()
    SQL
  }.freeze

  def up
    FUNCTIONS.each do |name, body|
      create_trigger_function(name, replace: true) { body }
    end

    create_triggers = TRIGGERS.map { |name, definition| "CREATE OR REPLACE TRIGGER #{name} #{definition}" }

    with_lock_retries do
      execute(create_triggers.join(";\n"))
    end
  end

  def down
    drop_triggers = TRIGGERS.keys.map { |name| "DROP TRIGGER IF EXISTS #{name} ON #{TABLE}" }

    with_lock_retries do
      execute(drop_triggers.join(";\n"))
    end

    FUNCTIONS.each_key do |name|
      drop_function(name, if_exists: true)
    end
  end
end
