# frozen_string_literal: true

class CreateAiTokenDailyUsages < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::PartitioningMigrationHelpers

  milestone '19.6'

  disable_ddl_transaction!

  TABLE_NAME = :ai_token_daily_usages
  UNIQUE_INDEX_NAME = 'index_ai_token_daily_usages_on_unique_tuple'
  USER_INDEX_NAME = 'index_ai_token_daily_usages_on_user_id_and_usage_date'
  OPTIONS = {
    primary_key: [:id, :usage_date],
    options: 'PARTITION BY RANGE (usage_date)',
    if_not_exists: true
  }.freeze

  def up
    create_table TABLE_NAME, **OPTIONS do |t|
      t.bigserial :id, null: false
      t.timestamps_with_timezone null: false
      t.bigint :organization_id, null: false
      t.bigint :user_id, null: false
      t.bigint :input_tokens, null: false, default: 0
      t.bigint :output_tokens, null: false, default: 0
      t.bigint :events_count, null: false, default: 0
      t.date :usage_date, null: false
      t.integer :feature, limit: 2, null: false
      t.bigint :traversal_ids, array: true, null: false, default: []
      t.text :model, null: false, limit: 255

      t.check_constraint 'input_tokens >= 0', name: 'check_ai_token_daily_usages_input_tokens_non_negative'
      t.check_constraint 'output_tokens >= 0', name: 'check_ai_token_daily_usages_output_tokens_non_negative'
      t.check_constraint 'events_count >= 0', name: 'check_ai_token_daily_usages_events_count_non_negative'

      t.index [:organization_id, :traversal_ids, :user_id, :feature, :model, :usage_date],
        unique: true, name: UNIQUE_INDEX_NAME
      t.index [:user_id, :usage_date], name: USER_INDEX_NAME
    end

    add_concurrent_partitioned_foreign_key TABLE_NAME, :organizations, column: :organization_id, on_delete: :cascade
  end

  def down
    drop_table TABLE_NAME, if_exists: true
  end
end
