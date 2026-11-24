# frozen_string_literal: true

class CreateDuoWorkflowsModelAliases < ClickHouse::Migration
  # Raw `model_used` spelling to hosting-neutral model key, written by
  # ClickHouse::DuoWorkflowsModelAliasesSyncCronWorker and read through a dictionary.
  # See https://gitlab.com/gitlab-org/gitlab/-/work_items/631302
  def up
    execute <<~SQL
      CREATE TABLE IF NOT EXISTS duo_workflows_model_aliases
      (
        model_used String,
        model_key String,
        hosting LowCardinality(String),
        version DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC'),
        deleted Bool DEFAULT false
      )
      ENGINE = ReplacingMergeTree(version, deleted)
      ORDER BY model_used
      SETTINGS index_granularity = 8192
    SQL
  end

  def down
    execute <<~SQL
      DROP TABLE IF EXISTS duo_workflows_model_aliases
    SQL
  end
end
