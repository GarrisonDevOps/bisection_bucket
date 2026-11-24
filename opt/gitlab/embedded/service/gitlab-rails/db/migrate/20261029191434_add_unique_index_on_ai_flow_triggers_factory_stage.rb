# frozen_string_literal: true

class AddUniqueIndexOnAiFlowTriggersFactoryStage < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  INDEX_NAME = 'index_ai_flow_triggers_on_project_id_and_factory_stage'

  def up
    add_concurrent_index :ai_flow_triggers, [:project_id, :factory_stage],
      unique: true, where: 'factory_stage IS NOT NULL', name: INDEX_NAME
  end

  # Reversibility tested on a Database Lab clone of gitlab-production-main: the index was
  # dropped and recreated against the full 1.6M-row table.
  def down
    remove_concurrent_index_by_name :ai_flow_triggers, INDEX_NAME
  end
end
