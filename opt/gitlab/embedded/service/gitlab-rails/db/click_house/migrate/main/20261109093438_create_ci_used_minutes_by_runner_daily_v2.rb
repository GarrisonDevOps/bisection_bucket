# frozen_string_literal: true

class CreateCiUsedMinutesByRunnerDailyV2 < ClickHouse::Migration
  def up
    execute <<~SQL
      CREATE TABLE IF NOT EXISTS ci_used_minutes_by_runner_daily_v2
      (
        finished_at_bucket DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC'),
        runner_type UInt8 DEFAULT 0,
        project_id UInt64 DEFAULT 0,
        status LowCardinality(String) DEFAULT '',
        runner_id UInt64 DEFAULT 0,
        count_builds AggregateFunction(count),
        total_duration SimpleAggregateFunction(sum, Int64)
      )
      ENGINE = AggregatingMergeTree()
      ORDER BY (finished_at_bucket, runner_type, project_id, status, runner_id)
    SQL
  end

  def down
    execute 'DROP TABLE IF EXISTS ci_used_minutes_by_runner_daily_v2'
  end
end
