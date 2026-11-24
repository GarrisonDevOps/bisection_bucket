# frozen_string_literal: true

class AddGitThrottleOverridesToProjectSettings < Gitlab::Database::Migration[2.3]
  milestone '19.6'

  # NULL means "no override": the project falls back to the instance-wide
  # ApplicationSetting threshold, which is the behavior for every existing row.
  def change
    add_column :project_settings, :throttle_unauthenticated_git_http_requests_per_period, :integer
    add_column :project_settings, :throttle_authenticated_git_http_requests_per_period, :integer
    add_column :project_settings, :throttle_authenticated_git_lfs_requests_per_period, :integer
  end
end
