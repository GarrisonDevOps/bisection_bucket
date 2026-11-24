# frozen_string_literal: true

# The _v2 table only held the evaluation run of the v2 session credits sync. The cutover
# (https://gitlab.com/gitlab-org/gitlab/-/merge_requests/263805) pointed the sync at
# duo_workflow_session_enrichments, and nothing has read or written this table since.
class DropDuoWorkflowSessionEnrichmentsV2 < ClickHouse::Migration
  def up
    execute <<~SQL
      DROP TABLE IF EXISTS duo_workflow_session_enrichments_v2
    SQL
  end

  def down
    execute <<~SQL
      CREATE TABLE IF NOT EXISTS duo_workflow_session_enrichments_v2
      (
        workflow_id Int64 CODEC(DoubleDelta, ZSTD(1)),
        credits_used Decimal64(4) DEFAULT 0 CODEC(ZSTD(1)),
        model_used LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
        credits_by_model Map(LowCardinality(String), Decimal64(4)) CODEC(ZSTD(1)),
        updated_at DateTime64(6, 'UTC') CODEC(Delta(8), ZSTD(1))
      )
      ENGINE = ReplacingMergeTree(updated_at)
      ORDER BY workflow_id
    SQL
  end
end
