# frozen_string_literal: true

# Queues a project_authorizations refresh for a new project, and for a project
# moved to another namespace, in the same transaction as the write, whatever
# made it.
class AddAuthzRefreshTriggersToProjects < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::SchemaHelpers

  milestone '19.6'

  disable_ddl_transaction!

  TABLE = :projects

  # Authz::ProjectAuthorizations::RefreshEvent.target_types[:project]
  PROJECT = 1

  FUNCTIONS = {
    authz_refresh_on_projects_insert: <<~SQL,
      INSERT INTO authz_refresh_events (target_type, target_id)
      SELECT #{PROJECT}, p.id FROM changed_rows p;
      RETURN NULL;
    SQL
    authz_refresh_on_projects_update: <<~SQL
      INSERT INTO authz_refresh_events (target_type, target_id) VALUES (#{PROJECT}, NEW.id);
      RETURN NULL;
    SQL
  }.freeze

  TRIGGERS = {
    trigger_authz_refresh_on_projects_insert: <<~SQL,
      AFTER INSERT ON projects REFERENCING NEW TABLE AS changed_rows
      FOR EACH STATEMENT EXECUTE FUNCTION authz_refresh_on_projects_insert()
    SQL
    trigger_authz_refresh_on_projects_update: <<~SQL
      AFTER UPDATE ON projects FOR EACH ROW
      WHEN (OLD.namespace_id IS DISTINCT FROM NEW.namespace_id)
      EXECUTE FUNCTION authz_refresh_on_projects_update()
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
