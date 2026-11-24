# frozen_string_literal: true

class AddIndexScanResultPolicyViolationsRunningOnUpdatedAt < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  INDEX_NAME = 'idx_scan_result_policy_violations_running_updated_at_id'
  RUNNING = 0

  def up
    add_concurrent_index :scan_result_policy_violations, %i[updated_at id],
      where: "status = #{RUNNING}", name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name :scan_result_policy_violations, INDEX_NAME
  end
end
