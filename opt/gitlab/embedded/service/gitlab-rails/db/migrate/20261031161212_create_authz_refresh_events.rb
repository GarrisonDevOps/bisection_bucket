# frozen_string_literal: true

class CreateAuthzRefreshEvents < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  TABLE_NAME = :authz_refresh_events
  OPTIONS = {
    primary_key: [:id, :partition],
    options: 'PARTITION BY LIST (partition)',
    if_not_exists: true
  }.freeze

  def up
    create_table TABLE_NAME, **OPTIONS do |t|
      t.bigserial :id, null: false
      t.bigint :partition, null: false, default: 1
      t.bigint :target_id, null: false
      t.bigint :scope_id
      t.bigint :cursor
      t.datetime_with_timezone :visible_at
      t.datetime_with_timezone :created_at, null: false, default: -> { 'now()' }
      t.datetime_with_timezone :first_queued_at, null: false, default: -> { 'now()' }
      t.integer :target_type, limit: 2, null: false
      t.integer :attempts, limit: 2, null: false, default: 0
      t.integer :status, limit: 2, null: false, default: 1

      t.index :id, where: 'status = 1', name: 'index_authz_refresh_events_pending'
      t.check_constraint '(target_type IN (2, 3, 7)) = (scope_id IS NOT NULL)',
        name: 'check_authz_refresh_events_scope_id'
    end

    execute(<<~SQL)
      CREATE TABLE IF NOT EXISTS gitlab_partitions_dynamic.#{TABLE_NAME}_1
      PARTITION OF #{TABLE_NAME} FOR VALUES IN (1);
    SQL
  end

  def down
    drop_table TABLE_NAME, if_exists: true
  end
end
