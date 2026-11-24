# frozen_string_literal: true

class AddFactoryStageToAiFlowTriggers < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :ai_flow_triggers, :factory_stage, :smallint
  end
end
