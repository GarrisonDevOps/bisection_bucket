# frozen_string_literal: true

# Queues a project_authorizations refresh of a user when they become active
# again, in the same transaction as the write, whatever made it. Refreshes
# skip blocked users, so their rows are brought up to date then.
class AddAuthzRefreshTriggerToUsers < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::SchemaHelpers

  milestone '19.6'

  disable_ddl_transaction!

  TABLE = :users

  # Authz::ProjectAuthorizations::RefreshEvent.target_types[:user]
  USER = 4

  FUNCTIONS = {
    authz_refresh_on_users_activated: <<~SQL
      INSERT INTO authz_refresh_events (target_type, target_id) VALUES (#{USER}, NEW.id);
      RETURN NULL;
    SQL
  }.freeze

  # users is large and updated often, so the WHEN clause keeps every other update
  # from calling the function.
  TRIGGERS = {
    trigger_authz_refresh_on_users_activated: <<~SQL
      AFTER UPDATE ON users FOR EACH ROW
      WHEN (NEW.state = 'active' AND OLD.state IS DISTINCT FROM 'active')
      EXECUTE FUNCTION authz_refresh_on_users_activated()
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
