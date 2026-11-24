# frozen_string_literal: true

class DropAiEventsCounts < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!
  milestone '19.7'

  TABLE_NAME = :ai_events_counts

  def up
    with_lock_retries do
      drop_table TABLE_NAME, if_exists: true
    end
  end

  def down
    opts = {
      primary_key: [:id, :events_date],
      options: 'PARTITION BY RANGE (events_date)',
      if_not_exists: true
    }

    create_table TABLE_NAME, **opts do |t|
      t.bigserial :id, null: false
      t.date :events_date, null: false
      t.bigint :namespace_id
      t.bigint :user_id, null: false, index: true
      t.bigint :organization_id, null: false, index: true
      t.integer :event, limit: 2, null: false
      t.integer :total_occurrences, null: false, default: 0
    end

    add_index TABLE_NAME, [:events_date, :namespace_id, :event, :user_id],
      unique: true,
      include: [:total_occurrences],
      nulls_not_distinct: true,
      name: 'idx_ai_events_counts_unique_tuple',
      if_not_exists: true
  end
end
