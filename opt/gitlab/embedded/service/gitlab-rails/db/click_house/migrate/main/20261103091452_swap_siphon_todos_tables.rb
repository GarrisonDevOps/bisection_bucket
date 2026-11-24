# frozen_string_literal: true

class SwapSiphonTodosTables < ClickHouse::Migration
  # MVs bind to their source and target tables by name, so the order below matters:
  # the new pg_pkey_ordered table keeps receiving inserts at every step, and no MV
  # selects user_id into a pg_pkey_ordered table that lacks it (that fails inserts).
  def up
    execute <<~SQL
      CREATE MATERIALIZED VIEW IF NOT EXISTS siphon_todos_pg_pkey_ordered_new_mv
      TO siphon_todos_pg_pkey_ordered
      AS
      SELECT
        id,
        traversal_path,
        _siphon_replicated_at,
        _siphon_deleted
      FROM siphon_todos
    SQL

    execute 'DROP VIEW IF EXISTS siphon_todos_pg_pkey_ordered_mv'

    safe_table_swap('siphon_todos', 'siphon_todos_v2')
    safe_table_swap('siphon_todos_pg_pkey_ordered', 'siphon_todos_v2_pg_pkey_ordered')

    execute 'DROP VIEW IF EXISTS siphon_todos_v2_mv'
    execute 'DROP VIEW IF EXISTS siphon_todos_v2_pg_pkey_ordered_mv'
    execute 'RENAME TABLE siphon_todos_pg_pkey_ordered_new_mv TO siphon_todos_pg_pkey_ordered_mv'
  end

  def down
    execute 'DROP VIEW IF EXISTS siphon_todos_pg_pkey_ordered_mv'

    safe_table_swap('siphon_todos', 'siphon_todos_v2')
    safe_table_swap('siphon_todos_pg_pkey_ordered', 'siphon_todos_v2_pg_pkey_ordered')

    execute <<~SQL
      CREATE MATERIALIZED VIEW IF NOT EXISTS siphon_todos_pg_pkey_ordered_mv
      TO siphon_todos_pg_pkey_ordered
      AS
      SELECT
        id,
        user_id,
        traversal_path,
        _siphon_replicated_at,
        _siphon_deleted
      FROM siphon_todos
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
end
