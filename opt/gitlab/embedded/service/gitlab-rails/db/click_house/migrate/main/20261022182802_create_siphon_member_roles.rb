# frozen_string_literal: true

class CreateSiphonMemberRoles < ClickHouse::Migration
  def up
    execute <<-SQL
      CREATE TABLE IF NOT EXISTS siphon_member_roles
      (
        id Int64 CODEC(DoubleDelta, ZSTD),
        namespace_id Nullable(Int64),
        created_at DateTime64(6, 'UTC') CODEC(Delta, ZSTD(1)),
        updated_at DateTime64(6, 'UTC') CODEC(Delta, ZSTD(1)),
        base_access_level Nullable(Int64),
        name String DEFAULT 'Custom',
        description Nullable(String),
        occupies_seat Bool DEFAULT false CODEC(ZSTD(1)),
        permissions String DEFAULT '{}',
        organization_id Nullable(Int64),
        traversal_path String DEFAULT multiIf(coalesce(namespace_id, 0) != 0, dictGetOrDefault('namespace_traversal_paths_dict', 'traversal_path', namespace_id, '0/'), coalesce(organization_id, 0) != 0, dictGetOrDefault('organization_traversal_paths_dict', 'traversal_path', organization_id, '0/'), '0/') CODEC(ZSTD(3)),
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
      DROP TABLE IF EXISTS siphon_member_roles
    SQL
  end
end
