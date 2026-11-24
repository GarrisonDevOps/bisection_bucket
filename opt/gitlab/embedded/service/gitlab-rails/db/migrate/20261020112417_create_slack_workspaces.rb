# frozen_string_literal: true

class CreateSlackWorkspaces < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    create_table :slack_workspaces do |t|
      t.bigint :duo_namespace_id, null: false, index: true
      t.timestamps_with_timezone null: false
      t.text :team_id, null: false, limit: 255

      # One Duo group per Slack workspace, so the index is global, like
      # jira_connect_installations.forge_installation_xid. team_id also gets a Cells claim:
      # https://gitlab.com/gitlab-org/gitlab/-/work_items/633611
      t.index :team_id, unique: true
    end
  end
end
