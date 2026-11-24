# frozen_string_literal: true

class CreateSiphonGroupGroupLinks < ClickHouse::Migration
  def up
    execute <<-SQL
      CREATE TABLE IF NOT EXISTS siphon_group_group_links
      (
        id Int64 CODEC(DoubleDelta, ZSTD),
        created_at DateTime64(6, 'UTC') CODEC(Delta, ZSTD(1)),
        updated_at DateTime64(6, 'UTC') CODEC(Delta, ZSTD(1)),
        shared_group_id Int64,
        shared_with_group_id Int64,
        expires_at Nullable(Date32),
        group_access Int16 DEFAULT 30,
        member_role_id Nullable(Int64),
        traversal_path String DEFAULT multiIf(coalesce(shared_group_id, 0) != 0, dictGetOrDefault('namespace_traversal_paths_dict', 'traversal_path', shared_group_id, '0/'), '0/') CODEC(ZSTD(3)),
        _siphon_replicated_at DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC') CODEC(ZSTD(1)),
        _siphon_deleted Bool DEFAULT FALSE CODEC(ZSTD(1)),
        _siphon_watermark DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC') CODEC(ZSTD(1)),
        INDEX idx_siphon_watermark_minmax _siphon_watermark TYPE minmax GRANULARITY 1
      )
      ENGINE = ReplacingMergeTree(_siphon_replicated_at, _siphon_deleted)
      PRIMARY KEY (traversal_path, id)
      SETTINGS index_granularity = 2048
    SQL
  end

  def down
    execute <<-SQL
      DROP TABLE IF EXISTS siphon_group_group_links
    SQL
  end
end
