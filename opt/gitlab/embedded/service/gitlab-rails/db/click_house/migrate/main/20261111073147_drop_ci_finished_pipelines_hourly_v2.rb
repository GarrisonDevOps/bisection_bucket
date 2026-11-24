# frozen_string_literal: true

class DropCiFinishedPipelinesHourlyV2 < ClickHouse::Migration
  def up
    execute 'DROP TABLE IF EXISTS ci_finished_pipelines_hourly_v2'
  end

  def down
    # CH 26.7+ rejects name outside the sorting key on CREATE TABLE, but not on ADD COLUMN.
    execute <<~SQL
      CREATE TABLE IF NOT EXISTS ci_finished_pipelines_hourly_v2
      (
        path String DEFAULT '0/',
        status LowCardinality(String) DEFAULT '',
        source LowCardinality(String) DEFAULT '',
        ref String DEFAULT '',
        started_at_bucket DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC'),
        count_pipelines AggregateFunction(count),
        duration_quantile AggregateFunction(quantile, UInt64)
      )
      ENGINE = AggregatingMergeTree()
      ORDER BY (started_at_bucket, path, status, source, ref)
    SQL

    execute <<~SQL
      ALTER TABLE ci_finished_pipelines_hourly_v2
        ADD COLUMN IF NOT EXISTS name String DEFAULT ''
    SQL
  end
end
