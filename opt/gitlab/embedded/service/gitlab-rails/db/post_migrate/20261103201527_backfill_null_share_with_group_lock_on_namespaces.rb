# frozen_string_literal: true

class BackfillNullShareWithGroupLockOnNamespaces < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!
  milestone '19.6'
  restrict_gitlab_migration gitlab_schema: :gitlab_main_org

  # A NULL lock is enforced as locked, so set it to true to keep the same access.
  def up
    define_batchable_model(:namespaces)
      .where(share_with_group_lock: nil)
      .each_batch(of: 1_000) do |batch|
        batch.update_all(share_with_group_lock: true)
      end
  end

  def down
    # no-op
  end
end
