# frozen_string_literal: true

class DropCiUsedMinutesByRunnerDailyV2 < ClickHouse::Migration
  def up
    execute 'DROP TABLE IF EXISTS ci_used_minutes_by_runner_daily_v2'
  end

  def down
    # CH 26.7+ rejects project_id outside the sorting key on CREATE TABLE, but not on ADD COLUMN.
    execute <<~SQL
      CREATE TABLE IF NOT EXISTS ci_used_minutes_by_runner_daily_v2
      (
        finished_at_bucket DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC'),
        runner_type UInt8 DEFAULT 0,
        status LowCardinality(String) DEFAULT '',
        runner_id UInt64 DEFAULT 0,
        count_builds AggregateFunction(count),
        total_duration SimpleAggregateFunction(sum, Int64)
      )
      ENGINE = AggregatingMergeTree()
      ORDER BY (finished_at_bucket, runner_type, status, runner_id)
    SQL

    execute <<~SQL
      ALTER TABLE ci_used_minutes_by_runner_daily_v2
        ADD COLUMN IF NOT EXISTS project_id UInt64 DEFAULT 0
    SQL
  end
end
