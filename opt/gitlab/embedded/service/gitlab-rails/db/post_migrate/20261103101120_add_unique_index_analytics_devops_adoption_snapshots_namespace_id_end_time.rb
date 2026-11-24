# frozen_string_literal: true

class AddUniqueIndexAnalyticsDevopsAdoptionSnapshotsNamespaceIdEndTime < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  TABLE_NAME = :analytics_devops_adoption_snapshots
  INDEX_NAME = 'index_devops_adoption_snapshots_on_namespace_id_and_end_time'

  def up
    add_concurrent_index TABLE_NAME, [:namespace_id, :end_time], unique: true, name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name TABLE_NAME, INDEX_NAME
  end
end
