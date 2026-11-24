# frozen_string_literal: true

# Seeds the Slack workspace scope tables, which are empty in the upgrade stop dump, so migrations
# touching them were never exercised by db:migrate:multi-version-upgrade.
class Gitlab::Seeder::SlackWorkspaceScopes # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  SCOPE_NAMES = %w[chat:write commands].freeze
  SLACK_TEAM_ID = 'T-SEEDED'

  attr_reader :project

  def initialize
    @project = Project.order(:id).first
  end

  # `update_scopes` creates the scopes and the join rows together and sets the sharding key from
  # the integration, so both tables are filled the way the application fills them.
  def seed!
    integration = slack_integration
    return warn "\nSkipping slack scope seeds: no project available" if integration.nil?

    ::Integrations::SlackWorkspace::IntegrationApiScope.update_scopes(
      SlackIntegration.where(id: integration.id),
      SCOPE_NAMES.map { |name| { name: name } })
    print '.'
  end

  private

  # The dump carries Slack integrations, but a freshly seeded database does not, so one is created
  # when it is missing rather than leaving the two scope tables empty there.
  def slack_integration
    existing = SlackIntegration.order(:id).first
    return existing if existing
    return if project.nil?

    app = ::Integrations::GitlabSlackApplication.find_by(project_id: project.id) ||
      ::Integrations::GitlabSlackApplication.create!(project: project, active: true)

    SlackIntegration.create!(integration: app, project: project, team_id: SLACK_TEAM_ID,
      team_name: 'Seeded Team', alias: "seeded-#{project.id}", user_id: 'U-SEEDED')
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating slack workspace scope data"

  Gitlab::Seeder::SlackWorkspaceScopes.new.seed!
end
