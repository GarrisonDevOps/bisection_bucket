# frozen_string_literal: true

# Gives db:migrate:multi-version-upgrade a row to exercise.
Gitlab::Seeder.quiet do
  group = Group.top_level.first
  next warn "\nSkipping slack_workspaces seeds: no top-level group available" unless group

  ::Integrations::SlackWorkspace::Workspace.find_or_create_by!(team_id: 'T_DEV_FIXTURE') do |workspace|
    workspace.duo_namespace = group
  end

  print '.'
end
