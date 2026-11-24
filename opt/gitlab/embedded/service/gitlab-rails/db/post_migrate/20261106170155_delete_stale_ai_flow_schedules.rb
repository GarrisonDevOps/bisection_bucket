# frozen_string_literal: true

class DeleteStaleAiFlowSchedules < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  restrict_gitlab_migration gitlab_schema: :gitlab_main_org
  disable_ddl_transaction!

  BATCH_SIZE = 500

  SCHEDULED_EVENT_TYPE = 9

  def up
    define_batchable_model('ai_flow_schedules').each_batch(of: BATCH_SIZE) do |batch|
      batch.where(stale_condition, SCHEDULED_EVENT_TYPE).delete_all
    end
  end

  def down
    # no-op: a schedule whose trigger no longer has the scheduled event type must not
    # fire, and nothing records which rows were deleted.
  end

  private

  def stale_condition
    <<~SQL.squish
      NOT EXISTS (
        SELECT 1
        FROM ai_flow_triggers
        WHERE ai_flow_triggers.id = ai_flow_schedules.ai_flow_trigger_id
          AND ai_flow_triggers.event_types @> ARRAY[?]::smallint[]
      )
    SQL
  end
end
