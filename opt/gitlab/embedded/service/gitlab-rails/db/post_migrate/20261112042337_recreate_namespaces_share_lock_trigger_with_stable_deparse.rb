# frozen_string_literal: true

# The share-lock trigger's `NEW.type IN ('Group', 'User')` compiles to a
# varchar[]->text[] coercion that PostgreSQL 16 and 17 deparse differently, so
# db/structure.sql never matches a re-dump and db:check-migrations fails on
# every MR that adds a migration. Scalar comparisons dump identically on both.
class RecreateNamespacesShareLockTriggerWithStableDeparse < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  TRIGGER_NAME = :trigger_authz_refresh_on_namespaces_share_lock_update

  def up
    recreate_with("(NEW.type = 'Group' OR NEW.type = 'User')")
  end

  def down
    recreate_with("NEW.type IN ('Group', 'User')")
  end

  private

  def recreate_with(type_condition)
    with_lock_retries do
      execute(<<~SQL)
        CREATE OR REPLACE TRIGGER #{TRIGGER_NAME}
        AFTER UPDATE ON namespaces FOR EACH ROW
        WHEN (#{type_condition} AND OLD.share_with_group_lock IS DISTINCT FROM NEW.share_with_group_lock)
        EXECUTE FUNCTION authz_refresh_on_namespaces_share_lock()
      SQL
    end
  end
end
