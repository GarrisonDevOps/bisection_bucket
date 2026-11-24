# frozen_string_literal: true

# Duo usage events moved to ai_usage_events in June 2025; nothing writes to or reads these tables since.
# See https://gitlab.com/gitlab-org/gitlab/-/work_items/638418
class DropLegacyDuoEventTables < ClickHouse::Migration
  TABLES = %w[
    code_suggestion_events
    duo_chat_events
    duo_chat_events_daily
    troubleshoot_job_events
  ].freeze

  def up
    TABLES.each do |table|
      execute <<~SQL
        DROP TABLE IF EXISTS #{table}
      SQL
    end
  end

  def down
    execute <<~SQL
      CREATE TABLE IF NOT EXISTS code_suggestion_events
      (
        `user_id` UInt64 DEFAULT 0,
        `event` UInt8 DEFAULT 0,
        `timestamp` DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC'),
        `namespace_path` String DEFAULT '0/',
        `unique_tracking_id` String DEFAULT '',
        `language` LowCardinality(String) DEFAULT '',
        `suggestion_size` UInt64 DEFAULT 0,
        `branch_name` String DEFAULT ''
      )
      ENGINE = ReplacingMergeTree
      PARTITION BY toYear(timestamp)
      ORDER BY (namespace_path, user_id, event, timestamp)
      SETTINGS index_granularity = 8192
    SQL

    execute <<~SQL
      CREATE TABLE IF NOT EXISTS duo_chat_events
      (
        `user_id` UInt64 DEFAULT 0,
        `event` UInt8 DEFAULT 0,
        `namespace_path` String DEFAULT '0/',
        `timestamp` DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC')
      )
      ENGINE = ReplacingMergeTree
      PARTITION BY toYear(timestamp)
      ORDER BY (namespace_path, user_id, event, timestamp)
      SETTINGS index_granularity = 8192
    SQL

    execute <<~SQL
      CREATE TABLE IF NOT EXISTS duo_chat_events_daily
      (
        `namespace_path` String DEFAULT '0/',
        `user_id` UInt64 DEFAULT 0,
        `date` Date32 DEFAULT toDate(now64()),
        `event` UInt8 DEFAULT 0,
        `occurrences` UInt64 DEFAULT 0
      )
      ENGINE = SummingMergeTree
      PARTITION BY toYear(date)
      ORDER BY (namespace_path, user_id, date, event)
      SETTINGS index_granularity = 64
    SQL

    execute <<~SQL
      CREATE TABLE IF NOT EXISTS troubleshoot_job_events
      (
        `user_id` UInt64 DEFAULT 0,
        `timestamp` DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC'),
        `job_id` UInt64 DEFAULT 0,
        `project_id` UInt64 DEFAULT 0,
        `event` UInt8 DEFAULT 0,
        `namespace_path` String DEFAULT '',
        `pipeline_id` UInt64 DEFAULT 0,
        `merge_request_id` UInt64 DEFAULT 0
      )
      ENGINE = ReplacingMergeTree
      PARTITION BY toYear(timestamp)
      ORDER BY (user_id, event, namespace_path, timestamp)
      SETTINGS index_granularity = 8192
    SQL
  end
end
