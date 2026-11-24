# frozen_string_literal: true

# Queues a project_authorizations refresh for the projects under a namespace
# when it moves to another parent or owner, and for its own shared projects
# when its share lock changes, in the same transaction as the write, whatever
# made it.
class AddAuthzRefreshTriggersToNamespaces < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::SchemaHelpers

  milestone '19.6'

  disable_ddl_transaction!

  TABLE = :namespaces

  # Authz::ProjectAuthorizations::RefreshEvent.target_types
  NAMESPACE_SUBTREE = 5
  NAMESPACE_PROJECT_GROUP_LINKS = 6

  FUNCTIONS = {
    authz_refresh_on_namespaces_subtree: <<~SQL,
      INSERT INTO authz_refresh_events (target_type, target_id) VALUES (#{NAMESPACE_SUBTREE}, NEW.id);
      RETURN NULL;
    SQL
    authz_refresh_on_namespaces_share_lock: <<~SQL
      INSERT INTO authz_refresh_events (target_type, target_id) VALUES (#{NAMESPACE_PROJECT_GROUP_LINKS}, NEW.id);
      RETURN NULL;
    SQL
  }.freeze

  # Project namespaces never grant access themselves: a moved project is covered
  # by the trigger on projects, and a project's share lock is its group's or owner's.
  TRIGGERS = {
    trigger_authz_refresh_on_namespaces_subtree_update: <<~SQL,
      AFTER UPDATE ON namespaces FOR EACH ROW
      WHEN ((NEW.type = 'Group' AND OLD.parent_id IS DISTINCT FROM NEW.parent_id)
        OR (NEW.type = 'User' AND OLD.owner_id IS DISTINCT FROM NEW.owner_id))
      EXECUTE FUNCTION authz_refresh_on_namespaces_subtree()
    SQL
    trigger_authz_refresh_on_namespaces_share_lock_update: <<~SQL
      AFTER UPDATE ON namespaces FOR EACH ROW
      WHEN (NEW.type IN ('Group', 'User') AND OLD.share_with_group_lock IS DISTINCT FROM NEW.share_with_group_lock)
      EXECUTE FUNCTION authz_refresh_on_namespaces_share_lock()
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
