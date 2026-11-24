# frozen_string_literal: true

class ReplacePackagesCleanupPoliciesNextRunAtIndex < Gitlab::Database::Migration[2.3]
  disable_ddl_transaction!
  milestone '19.6'

  TABLE_NAME = :packages_cleanup_policies
  OLD_INDEX_NAME = 'idx_enabled_pkgs_cleanup_policies_on_next_run_at_project_id'
  NEW_INDEX_NAME = 'idx_active_pkgs_cleanup_policies_on_next_run_at_project_id'

  def up
    add_concurrent_index TABLE_NAME, [:next_run_at, :project_id],
      where: "keep_n_duplicated_package_files <> 'all' OR delete_generic_packages_not_downloaded_in_days IS NOT NULL",
      name: NEW_INDEX_NAME

    remove_concurrent_index_by_name TABLE_NAME, OLD_INDEX_NAME
  end

  def down
    add_concurrent_index TABLE_NAME, [:next_run_at, :project_id],
      where: "keep_n_duplicated_package_files <> 'all'",
      name: OLD_INDEX_NAME

    remove_concurrent_index_by_name TABLE_NAME, NEW_INDEX_NAME
  end
end
