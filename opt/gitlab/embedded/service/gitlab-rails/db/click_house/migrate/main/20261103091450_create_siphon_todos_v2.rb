# frozen_string_literal: true

class CreateSiphonTodosV2 < ClickHouse::Migration
  def up
    execute <<~SQL
      CREATE TABLE IF NOT EXISTS siphon_todos_v2
      (
        id Int64 CODEC(DoubleDelta, ZSTD),
        user_id Int64 CODEC(DoubleDelta, ZSTD),
        project_id Nullable(Int64),
        target_id Nullable(Int64),
        target_type LowCardinality(String),
        author_id Int64,
        action Int64,
        state LowCardinality(String),
        created_at DateTime64(6, 'UTC') CODEC(Delta, ZSTD(1)),
        updated_at DateTime64(6, 'UTC') CODEC(Delta, ZSTD(1)),
        commit_id Nullable(String),
        group_id Nullable(Int64),
        resolved_by_action Nullable(Int16),
        note_id Nullable(Int64),
        snoozed_until Nullable(DateTime64(6, 'UTC')),
        organization_id Nullable(Int64),
        traversal_path String DEFAULT multiIf(coalesce(project_id, 0) != 0, dictGetOrDefault('project_traversal_paths_dict', 'traversal_path', project_id, '0/'), coalesce(group_id, 0) != 0, dictGetOrDefault('namespace_traversal_paths_dict', 'traversal_path', group_id, '0/'), coalesce(organization_id, 0) != 0, dictGetOrDefault('organization_traversal_paths_dict', 'traversal_path', organization_id, '0/'), '0/') CODEC(ZSTD(3)),
        _siphon_replicated_at DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC') CODEC(ZSTD(1)),
        _siphon_deleted Bool DEFAULT FALSE CODEC(ZSTD(1)),
        _siphon_watermark DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC') CODEC(ZSTD(1)),
        INDEX idx_siphon_watermark_minmax _siphon_watermark TYPE minmax GRANULARITY 1
      )
      ENGINE = ReplacingMergeTree(_siphon_replicated_at, _siphon_deleted)
      PRIMARY KEY (traversal_path, id)
      SETTINGS index_granularity = 2048
    SQL

    execute <<~SQL
      CREATE TABLE IF NOT EXISTS siphon_todos_v2_pg_pkey_ordered
      (
        id Int64 CODEC(DoubleDelta, ZSTD),
        traversal_path String DEFAULT '0/' CODEC(ZSTD(3)),
        _siphon_replicated_at DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC') CODEC(ZSTD(1)),
        _siphon_deleted Bool DEFAULT FALSE CODEC(ZSTD(1))
      )
      ENGINE = ReplacingMergeTree(_siphon_replicated_at, _siphon_deleted)
      PRIMARY KEY (id, traversal_path)
      ORDER BY (id, traversal_path)
      SETTINGS index_granularity = 1024
    SQL

    execute <<~SQL
      CREATE MATERIALIZED VIEW IF NOT EXISTS siphon_todos_v2_pg_pkey_ordered_mv
      TO siphon_todos_v2_pg_pkey_ordered
      AS
      SELECT
        id,
        traversal_path,
        _siphon_replicated_at,
        _siphon_deleted
      FROM siphon_todos_v2
    SQL

    # Keeps siphon_todos_v2 in sync with new Siphon inserts until the swap.
    execute <<~SQL
      CREATE MATERIALIZED VIEW IF NOT EXISTS siphon_todos_v2_mv
      TO siphon_todos_v2
      AS
      SELECT
        id,
        user_id,
        project_id,
        target_id,
        target_type,
        author_id,
        action,
        state,
        created_at,
        updated_at,
        commit_id,
        group_id,
        resolved_by_action,
        note_id,
        snoozed_until,
        organization_id,
        traversal_path,
        _siphon_replicated_at,
        _siphon_deleted,
        _siphon_watermark
      FROM siphon_todos
    SQL
  end

  def down
    execute 'DROP VIEW IF EXISTS siphon_todos_v2_mv'
    execute 'DROP VIEW IF EXISTS siphon_todos_v2_pg_pkey_ordered_mv'
    execute 'DROP TABLE IF EXISTS siphon_todos_v2_pg_pkey_ordered'
    execute 'DROP TABLE IF EXISTS siphon_todos_v2'
  end
end
