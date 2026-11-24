# frozen_string_literal: true

class CopyDataToSiphonTodosV2 < ClickHouse::Migration
  BATCH_SIZE = 500_000

  COLUMNS = %i[
    id
    user_id
    project_id
    target_id
    target_type
    author_id
    action
    state
    created_at
    updated_at
    commit_id
    group_id
    resolved_by_action
    note_id
    snoozed_until
    organization_id
    traversal_path
    _siphon_replicated_at
    _siphon_deleted
    _siphon_watermark
  ].freeze

  def up
    builder = ClickHouse::Client::QueryBuilder.new('siphon_todos')
    iterator = ClickHouse::Iterator.new(query_builder: builder, connection: connection)

    # siphon_todos_v2_pg_pkey_ordered is populated through siphon_todos_v2_pg_pkey_ordered_mv.
    iterator.each_batch(column: :id, of: BATCH_SIZE) do |scope|
      execute("INSERT INTO siphon_todos_v2 (#{COLUMNS.join(', ')}) #{scope.select(*COLUMNS).to_sql}")
    end
  end

  def down
    # no-op: siphon_todos_v2 uses ReplacingMergeTree, so re-running the copy is idempotent.
  end
end
