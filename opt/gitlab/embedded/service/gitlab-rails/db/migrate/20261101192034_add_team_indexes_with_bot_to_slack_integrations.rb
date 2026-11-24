# frozen_string_literal: true

class AddTeamIndexesWithBotToSlackIntegrations < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  GROUP_INDEX_NAME = 'index_slack_integrations_on_team_id_and_group_id_with_bot'
  PROJECT_INDEX_NAME = 'index_slack_integrations_on_team_id_and_project_id_with_bot'

  # Lets `DuoGroupEligibility` check a workspace against every group and project of a hierarchy
  # with index-only scans, instead of reading a table row per id.
  def up
    add_concurrent_index :slack_integrations, [:team_id, :group_id],
      where: 'bot_user_id IS NOT NULL', name: GROUP_INDEX_NAME
    add_concurrent_index :slack_integrations, [:team_id, :project_id],
      where: 'bot_user_id IS NOT NULL', name: PROJECT_INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name :slack_integrations, PROJECT_INDEX_NAME
    remove_concurrent_index_by_name :slack_integrations, GROUP_INDEX_NAME
  end
end
