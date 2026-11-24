# frozen_string_literal: true

class AddGitThrottleOverridesIndexToProjectSettings < Gitlab::Database::Migration[2.3]
  milestone '19.6'

  disable_ddl_transaction!

  TABLE_NAME = :project_settings
  INDEX_NAME = 'index_project_settings_on_git_throttle_overrides'

  # Overrides are set on a handful of projects, so the partial index holds only
  # those rows. The rate limiter loads the whole set on a timer and must not have
  # to scan project_settings to do it.
  WHERE_CLAUSE = <<~SQL.squish
    throttle_unauthenticated_git_http_requests_per_period IS NOT NULL
    OR throttle_authenticated_git_http_requests_per_period IS NOT NULL
    OR throttle_authenticated_git_lfs_requests_per_period IS NOT NULL
  SQL

  def up
    add_concurrent_index(TABLE_NAME, :project_id, name: INDEX_NAME, where: WHERE_CLAUSE)
  end

  def down
    remove_concurrent_index_by_name(TABLE_NAME, INDEX_NAME)
  end
end
