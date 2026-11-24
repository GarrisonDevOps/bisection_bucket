# frozen_string_literal: true

class CleanupRemoveDuplicateDefaultTrackedContexts < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  restrict_gitlab_migration gitlab_schema: :gitlab_main_org

  MIGRATION = "RemoveDuplicateDefaultTrackedContexts"

  def up
    delete_batched_background_migration(MIGRATION, :projects, :id, [])
  end

  def down
    # no-op, the superseded migration must not be queued again
  end
end
