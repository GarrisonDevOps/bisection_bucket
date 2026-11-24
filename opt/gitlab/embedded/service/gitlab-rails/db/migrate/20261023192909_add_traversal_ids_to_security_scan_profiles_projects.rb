# frozen_string_literal: true

class AddTraversalIdsToSecurityScanProfilesProjects < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :security_scan_profiles_projects, :traversal_ids, :bigint, array: true, default: [], null: false
  end
end
