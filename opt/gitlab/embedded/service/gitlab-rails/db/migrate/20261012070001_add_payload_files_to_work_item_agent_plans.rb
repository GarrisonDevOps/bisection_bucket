# frozen_string_literal: true

class AddPayloadFilesToWorkItemAgentPlans < Gitlab::Database::Migration[2.3]
  milestone '19.6'

  disable_ddl_transaction!

  TABLE = :work_item_agent_plans

  def up
    add_column TABLE, :content_file, :text, if_not_exists: true
    add_column TABLE, :content_file_store, :smallint, default: 1, null: false, if_not_exists: true
    add_column TABLE, :readiness_score_feedback_file, :text, if_not_exists: true
    add_column TABLE, :readiness_score_feedback_file_store, :smallint, default: 1, null: false, if_not_exists: true

    add_text_limit TABLE, :content_file, 255
    add_text_limit TABLE, :readiness_score_feedback_file, 255
  end

  def down
    remove_column TABLE, :content_file, if_exists: true
    remove_column TABLE, :content_file_store, if_exists: true
    remove_column TABLE, :readiness_score_feedback_file, if_exists: true
    remove_column TABLE, :readiness_score_feedback_file_store, if_exists: true
  end
end
