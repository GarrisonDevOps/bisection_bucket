# frozen_string_literal: true

class CreateCiFinishedPipelinesHourlyV2 < ClickHouse::Migration
  def up
    execute <<~SQL
      CREATE TABLE IF NOT EXISTS ci_finished_pipelines_hourly_v2
      (
        path String DEFAULT '0/',
        status LowCardinality(String) DEFAULT '',
        source LowCardinality(String) DEFAULT '',
        ref String DEFAULT '',
        name String DEFAULT '',
        started_at_bucket DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC'),
        count_pipelines AggregateFunction(count),
        duration_quantile AggregateFunction(quantile, UInt64)
      )
      ENGINE = AggregatingMergeTree()
      ORDER BY (started_at_bucket, path, status, source, ref, name)
    SQL
  end

  def down
    execute 'DROP TABLE IF EXISTS ci_finished_pipelines_hourly_v2'
  end
end
