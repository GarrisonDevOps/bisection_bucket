# frozen_string_literal: true

class AddDuoScheduledTriggersEnabledToProjectSettings < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :project_settings, :duo_scheduled_triggers_enabled, :boolean, null: false, default: true
  end
end
