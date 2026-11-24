# frozen_string_literal: true

class BackfillWorkItemAgentPlansContentFile < Gitlab::Database::Migration[2.3]
  milestone '19.6'
  restrict_gitlab_migration gitlab_schema: :gitlab_main_org

  disable_ddl_transaction!

  BATCH_SIZE = 500

  def up
    each_batch_range(
      'work_item_agent_plans', connection: connection, column: :work_item_id, of: BATCH_SIZE
    ) do |min, max|
      connection.execute(<<~SQL)
        UPDATE work_item_agent_plans
        SET content_file = work_item_id || '.json',
            content_file_store = file_store
        WHERE work_item_id BETWEEN #{min} AND #{max}
          AND content_file IS NULL
      SQL
    end
  end

  def down
    # no-op: the column is nullable and the value is derivable, so nothing is lost.
  end
end
