# frozen_string_literal: true

# Queues a project_authorizations refresh of a user's access to a project or
# group when their membership is added, removed or changed, in the same
# transaction as the write, whatever made it.
class AddAuthzRefreshTriggersToMembers < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::SchemaHelpers

  milestone '19.6'

  disable_ddl_transaction!

  TABLE = :members

  # Authz::ProjectAuthorizations::RefreshEvent.target_types
  USER_IN_PROJECT = 2
  USER_IN_GROUP = 3

  # Gitlab::Access::MINIMAL_ACCESS
  MINIMAL_ACCESS = 5

  # Member::STATE_ACTIVE
  STATE_ACTIVE = 0

  INSERT_EVENTS = <<~SQL.chomp
    INSERT INTO authz_refresh_events (target_type, target_id, scope_id)
    SELECT DISTINCT CASE WHEN m.source_type = 'Project' THEN #{USER_IN_PROJECT} ELSE #{USER_IN_GROUP} END,
      m.user_id, m.source_id
  SQL

  # Matches Member.authorizable: pending invites, access requests, awaiting members
  # and Minimal Access members grant no project access.
  GRANTS_ACCESS = <<~SQL.squish
    m.user_id IS NOT NULL AND m.requested_at IS NULL AND m.state = #{STATE_ACTIVE}
    AND m.access_level > #{MINIMAL_ACCESS}
  SQL

  FUNCTIONS = {
    authz_refresh_on_members_statement: <<~SQL,
      #{INSERT_EVENTS}
      FROM changed_rows m
      WHERE #{GRANTS_ACCESS};
      RETURN NULL;
    SQL
    # Members deleted with their project or user need no refresh: the loose foreign keys on project_authorizations
    # remove those rows, and by then the project namespace or user row is gone. Group members are always queued, so
    # removing the group's shares in the same cascade can still capture them.
    authz_refresh_on_members_delete: <<~SQL,
      #{INSERT_EVENTS}
      FROM changed_rows m
      WHERE #{GRANTS_ACCESS}
        AND (m.source_type <> 'Project' OR EXISTS (SELECT 1 FROM namespaces n WHERE n.id = m.member_namespace_id))
        AND EXISTS (SELECT 1 FROM users u WHERE u.id = m.user_id);
      RETURN NULL;
    SQL
    # Either the old or the new row may have granted access, so each that does is
    # queued: the new row when requested_at goes from set to NULL, the old row when
    # access_level goes from Guest or above to Minimal Access.
    authz_refresh_on_members_update: <<~SQL
      #{INSERT_EVENTS}
      FROM (VALUES
          (OLD.user_id, OLD.source_id, OLD.source_type, OLD.requested_at, OLD.state, OLD.access_level),
          (NEW.user_id, NEW.source_id, NEW.source_type, NEW.requested_at, NEW.state, NEW.access_level))
        AS m (user_id, source_id, source_type, requested_at, state, access_level)
      WHERE #{GRANTS_ACCESS};
      RETURN NULL;
    SQL
  }.freeze

  TRIGGERS = {
    trigger_authz_refresh_on_members_insert: <<~SQL,
      AFTER INSERT ON members REFERENCING NEW TABLE AS changed_rows
      FOR EACH STATEMENT EXECUTE FUNCTION authz_refresh_on_members_statement()
    SQL
    trigger_authz_refresh_on_members_delete: <<~SQL,
      AFTER DELETE ON members REFERENCING OLD TABLE AS changed_rows
      FOR EACH STATEMENT EXECUTE FUNCTION authz_refresh_on_members_delete()
    SQL
    trigger_authz_refresh_on_members_update: <<~SQL
      AFTER UPDATE ON members FOR EACH ROW
      WHEN (OLD.user_id IS DISTINCT FROM NEW.user_id
        OR OLD.source_id IS DISTINCT FROM NEW.source_id
        OR OLD.source_type IS DISTINCT FROM NEW.source_type
        OR OLD.access_level IS DISTINCT FROM NEW.access_level
        OR OLD.state IS DISTINCT FROM NEW.state
        OR OLD.requested_at IS DISTINCT FROM NEW.requested_at)
      EXECUTE FUNCTION authz_refresh_on_members_update()
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
