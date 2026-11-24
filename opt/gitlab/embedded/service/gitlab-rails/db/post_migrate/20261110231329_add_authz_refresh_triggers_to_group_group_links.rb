# frozen_string_literal: true

# Queues a project_authorizations refresh when a group is shared with another
# group, the share is removed or it is changed, in the same transaction as the
# write, whatever made it.
class AddAuthzRefreshTriggersToGroupGroupLinks < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::SchemaHelpers

  milestone '19.6'

  disable_ddl_transaction!

  TABLE = :group_group_links

  # Authz::ProjectAuthorizations::RefreshEvent.target_types and .statuses
  USER_IN_GROUP = 3
  NAMESPACE_SUBTREE = 5
  GROUP_GROUP_LINK = 7
  PENDING = 1

  # Gitlab::Access::MINIMAL_ACCESS
  MINIMAL_ACCESS = 5

  # Member::STATE_ACTIVE
  STATE_ACTIVE = 0

  # Above this many captured memberships, as when a group with many members
  # and shares is deleted, the shared groups are queued for a recalculation of
  # all their users instead, which costs projects rather than users.
  CAPTURE_LIMIT = 10_000

  TRIGGERS = {
    trigger_authz_refresh_on_group_group_links_insert: <<~SQL,
      AFTER INSERT ON group_group_links REFERENCING NEW TABLE AS changed_rows
      FOR EACH STATEMENT EXECUTE FUNCTION authz_refresh_on_group_group_links_insert()
    SQL
    trigger_authz_refresh_on_group_group_links_delete: <<~SQL,
      AFTER DELETE ON group_group_links REFERENCING OLD TABLE AS changed_rows
      FOR EACH STATEMENT EXECUTE FUNCTION authz_refresh_on_group_group_links_delete()
    SQL
    trigger_authz_refresh_on_group_group_links_update: <<~SQL
      AFTER UPDATE ON group_group_links FOR EACH ROW
      WHEN (OLD.shared_group_id IS DISTINCT FROM NEW.shared_group_id
        OR OLD.shared_with_group_id IS DISTINCT FROM NEW.shared_with_group_id
        OR OLD.group_access IS DISTINCT FROM NEW.group_access)
      EXECUTE FUNCTION authz_refresh_on_group_group_links_update()
    SQL
  }.freeze

  # Captures who can lose access in the same transaction: the invited group's members, plus users with a queued
  # event for it, who just left. The pair's group_group_link event, expanded later, catches anyone who joined meanwhile.
  def self.capture_share_removal(removed_shares)
    members = <<~SQL.squish
      SELECT m.user_id FROM members m
      WHERE m.source_type = 'Namespace' AND m.source_id = l.shared_with_group_id AND m.user_id IS NOT NULL
        AND m.requested_at IS NULL AND m.state = #{STATE_ACTIVE} AND m.access_level > #{MINIMAL_ACCESS}
    SQL
    queued = <<~SQL.squish
      SELECT e.target_id FROM authz_refresh_events e
      WHERE e.target_type = #{USER_IN_GROUP} AND e.scope_id = l.shared_with_group_id AND e.status = #{PENDING}
    SQL
    # A deleted shared group needs no refresh: the loose foreign keys remove its projects' rows.
    removed = "(SELECT * FROM (#{removed_shares}) r (shared_group_id, shared_with_group_id) " \
      "WHERE EXISTS (SELECT 1 FROM namespaces n WHERE n.id = r.shared_group_id)) l"

    # When the invited group is deleted, this trigger can run before the members trigger has queued its members,
    # leaving nobody to capture, so the shared group is recalculated for all its users. Rails deletions take it too.
    <<~SQL.chomp
      INSERT INTO authz_refresh_events (target_type, target_id)
      SELECT DISTINCT #{NAMESPACE_SUBTREE}, l.shared_group_id FROM #{removed}
      WHERE NOT EXISTS (SELECT 1 FROM namespaces n WHERE n.id = l.shared_with_group_id);
      IF (SELECT count(*) FROM (SELECT 1 FROM #{removed} CROSS JOIN LATERAL (#{members} UNION ALL #{queued}) c
          LIMIT #{CAPTURE_LIMIT + 1}) capped) > #{CAPTURE_LIMIT} THEN
        INSERT INTO authz_refresh_events (target_type, target_id)
        SELECT DISTINCT #{NAMESPACE_SUBTREE}, l.shared_group_id FROM #{removed};
      ELSE
        INSERT INTO authz_refresh_events (target_type, target_id, scope_id)
        SELECT DISTINCT #{USER_IN_GROUP}, captured.user_id, l.shared_group_id
        FROM #{removed} CROSS JOIN LATERAL (#{members} UNION #{queued}) captured;
        INSERT INTO authz_refresh_events (target_type, target_id, scope_id)
        SELECT DISTINCT #{GROUP_GROUP_LINK}, l.shared_with_group_id, l.shared_group_id FROM #{removed};
      END IF;
    SQL
  end

  # A method rather than a constant, so specs can lower CAPTURE_LIMIT.
  def self.functions
    {
      # The group_group_link event is expanded later into the invited group's members.
      authz_refresh_on_group_group_links_insert: <<~SQL,
        INSERT INTO authz_refresh_events (target_type, target_id, scope_id)
        SELECT DISTINCT #{GROUP_GROUP_LINK}, l.shared_with_group_id, l.shared_group_id FROM changed_rows l;
        RETURN NULL;
      SQL
      authz_refresh_on_group_group_links_delete: <<~SQL,
        #{capture_share_removal('SELECT shared_group_id, shared_with_group_id FROM changed_rows')}
        RETURN NULL;
      SQL
      # A repointed share removes the old pair's access, like a delete, and grants
      # the new pair's.
      authz_refresh_on_group_group_links_update: <<~SQL
        IF OLD.shared_group_id IS DISTINCT FROM NEW.shared_group_id
          OR OLD.shared_with_group_id IS DISTINCT FROM NEW.shared_with_group_id THEN
          #{capture_share_removal('SELECT OLD.shared_group_id, OLD.shared_with_group_id')}
        END IF;
        INSERT INTO authz_refresh_events (target_type, target_id, scope_id)
        VALUES (#{GROUP_GROUP_LINK}, NEW.shared_with_group_id, NEW.shared_group_id);
        RETURN NULL;
      SQL
    }
  end

  def up
    self.class.functions.each do |name, body|
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

    self.class.functions.each_key do |name|
      drop_function(name, if_exists: true)
    end
  end
end
