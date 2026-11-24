# frozen_string_literal: true

class CreateSiphonDoraDailyMetrics < ClickHouse::Migration
  def up
    execute <<-SQL
      CREATE TABLE IF NOT EXISTS siphon_dora_daily_metrics
      (
        id Int64 CODEC(DoubleDelta, ZSTD),
        environment_id Int64,
        date Date32,
        deployment_frequency Nullable(Int64),
        lead_time_for_changes_in_seconds Nullable(Int64),
        time_to_restore_service_in_seconds Nullable(Int64),
        incidents_count Nullable(Int64),
        project_id Nullable(Int64),
        traversal_path String DEFAULT multiIf(coalesce(project_id, 0) != 0, dictGetOrDefault('project_traversal_paths_dict', 'traversal_path', project_id, '0/'), '0/') CODEC(ZSTD(3)),
        _siphon_replicated_at DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC') CODEC(ZSTD(1)),
        _siphon_deleted Bool DEFAULT FALSE CODEC(ZSTD(1)),
        _siphon_watermark DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC') CODEC(ZSTD(1)),
        INDEX idx_siphon_watermark_minmax _siphon_watermark TYPE minmax GRANULARITY 1
      )
      ENGINE = ReplacingMergeTree(_siphon_replicated_at, _siphon_deleted)
      PRIMARY KEY (traversal_path, date, environment_id, id)
      SETTINGS index_granularity = 2048
    SQL
  end

  def down
    execute <<-SQL
      DROP TABLE IF EXISTS siphon_dora_daily_metrics
    SQL
  end
end
