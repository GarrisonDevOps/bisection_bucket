# frozen_string_literal: true

class AddEnvironmentAndPrivateMessagingToAiGovernanceSessions < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :ai_governance_sessions, :environment, :smallint
    add_column :ai_governance_sessions, :private_messaging, :boolean, default: false, null: false
  end
end
