# frozen_string_literal: true

# Nothing reads or writes these tables since the add-on assignment sync workers went away in July 2026.
# See https://gitlab.com/gitlab-org/gitlab/-/work_items/611979
class DropAddOnAssignmentHistoryTables < ClickHouse::Migration
  def up
    execute <<~SQL
      DROP VIEW IF EXISTS user_addon_assignments_history_mv
    SQL

    %w[
      user_addon_assignments_history
      subscription_user_add_on_assignment_versions
      user_add_on_assignments_history
    ].each do |table|
      execute <<~SQL
        DROP TABLE IF EXISTS #{table}
      SQL
    end
  end

  def down
    execute <<~SQL
      CREATE TABLE IF NOT EXISTS subscription_user_add_on_assignment_versions
      (
        `id` UInt64,
        `organization_id` UInt64,
        `item_id` UInt64,
        `user_id` UInt64,
        `purchase_id` UInt64,
        `namespace_path` String,
        `add_on_name` String,
        `event` String,
        `created_at` DateTime64(6, 'UTC'),
        `version` DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC'),
        `deleted` Bool DEFAULT false
      )
      ENGINE = ReplacingMergeTree(version, deleted)
      ORDER BY (namespace_path, user_id, item_id, event, id)
      SETTINGS index_granularity = 8192
    SQL

    execute <<~SQL
      CREATE TABLE IF NOT EXISTS user_add_on_assignments_history
      (
        `assignment_id` UInt64,
        `namespace_path` String DEFAULT '0/',
        `user_id` UInt64,
        `purchase_id` UInt64,
        `add_on_name` String,
        `assigned_at` DateTime64(6, 'UTC'),
        `revoked_at` Nullable(DateTime64(6, 'UTC'))
      )
      ENGINE = ReplacingMergeTree(assignment_id)
      PARTITION BY toYear(assigned_at)
      ORDER BY (namespace_path, assigned_at, user_id)
      SETTINGS index_granularity = 8192
    SQL

    execute <<~SQL
      CREATE TABLE IF NOT EXISTS user_addon_assignments_history
      (
        `assignment_id` UInt64,
        `namespace_path` String DEFAULT '0/',
        `user_id` UInt64,
        `purchase_id` UInt64,
        `add_on_name` String,
        `assigned_at` AggregateFunction(min, Nullable(DateTime64(6, 'UTC'))),
        `revoked_at` AggregateFunction(max, Nullable(DateTime64(6, 'UTC')))
      )
      ENGINE = AggregatingMergeTree
      ORDER BY (namespace_path, user_id, assignment_id)
      SETTINGS index_granularity = 8192
    SQL

    execute <<~SQL
      CREATE MATERIALIZED VIEW IF NOT EXISTS user_addon_assignments_history_mv TO user_addon_assignments_history
      AS SELECT
        item_id AS assignment_id,
        namespace_path,
        purchase_id,
        add_on_name,
        user_id,
        minState(multiIf(event = 'create', created_at, NULL)) AS assigned_at,
        maxState(multiIf(event = 'destroy', created_at, NULL)) AS revoked_at
      FROM subscription_user_add_on_assignment_versions
      GROUP BY
        item_id,
        namespace_path,
        user_id,
        purchase_id,
        add_on_name
    SQL
  end
end
