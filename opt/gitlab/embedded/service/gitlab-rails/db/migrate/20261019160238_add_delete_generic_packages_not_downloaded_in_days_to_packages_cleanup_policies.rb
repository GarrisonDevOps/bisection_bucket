# frozen_string_literal: true

class AddDeleteGenericPackagesNotDownloadedInDaysToPackagesCleanupPolicies < Gitlab::Database::Migration[2.3]
  disable_ddl_transaction!
  milestone '19.6'

  CONSTRAINT_NAME = 'check_packages_cleanup_policies_generic_not_downloaded_days'

  def up
    with_lock_retries do
      add_column :packages_cleanup_policies, :delete_generic_packages_not_downloaded_in_days, :integer,
        if_not_exists: true
    end

    add_check_constraint :packages_cleanup_policies,
      'delete_generic_packages_not_downloaded_in_days > 0 AND delete_generic_packages_not_downloaded_in_days <= 3650',
      CONSTRAINT_NAME
  end

  def down
    with_lock_retries do
      remove_column :packages_cleanup_policies, :delete_generic_packages_not_downloaded_in_days, if_exists: true
    end
  end
end
