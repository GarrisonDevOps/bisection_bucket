# frozen_string_literal: true

class RescheduleRemoveDuplicateDefaultTrackedContexts < Gitlab::Database::Migration[2.3]
  milestone '19.2'
  restrict_gitlab_migration gitlab_schema: :gitlab_main_org

  MIGRATION = "RemoveDuplicateDefaultTrackedContexts"

  def up
    # no-op: superseded by MarkDuplicateDefaultTrackedContextsAsNonDefault
  end

  def down
    # no-op
  end
end
