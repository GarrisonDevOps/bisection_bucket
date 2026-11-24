# frozen_string_literal: true

# Workspace and runner cost setting tables are empty in the upgrade stop dump, so migrations
# touching them are never exercised by db:migrate:multi-version-upgrade.
class Gitlab::Seeder::WorkspacesAndRunnerCostSettings # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  WORKSPACE_NAME = 'seeded-workspace'
  WORKSPACE_NAMESPACE = 'gl-seeded-workspace'
  PROJECT_REF = 'main'
  VARIABLE_KEY = 'SEEDED_VARIABLE'
  TOKEN_NAME = 'Seeded workspace token'

  attr_reader :user

  def initialize
    @user = ::Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin
  end

  def seed!
    seed_workspace_records
    seed_runner_cost_setting
  end

  private

  def seed_workspace_records
    workspace = existing_workspace || create_workspace
    return if workspace.nil?

    seed_workspace_variables(workspace)
    seed_workspace_agentk_state(workspace)
  end

  def existing_workspace
    ::RemoteDevelopment::Workspace.find_by(name: WORKSPACE_NAME)
  end

  def create_workspace
    agent = ::Clusters::Agent.with_remote_development_enabled.order(:id).first
    return warn "\nSkipping workspace seeds: no agent with an enabled config available" if agent.nil?
    return warn "\nSkipping workspace seeds: no seeded admin available" if user.nil?

    # A running desired state is what writes the workspace token, through the model's own callback.
    ::RemoteDevelopment::Workspace.create!(
      user: user, project: agent.project, agent: agent,
      personal_access_token: workspace_personal_access_token(agent.project),
      name: WORKSPACE_NAME, namespace: WORKSPACE_NAMESPACE, project_ref: PROJECT_REF,
      desired_state: ::RemoteDevelopment::WorkspaceOperations::States::RUNNING,
      actual_state: ::RemoteDevelopment::WorkspaceOperations::States::CREATION_REQUESTED)
  end

  # Terminating a workspace revokes its token, so the workspace gets one of its own rather than
  # whichever token the admin already has.
  def workspace_personal_access_token(project)
    ::PersonalAccessToken.find_by(user_id: user.id, name: TOKEN_NAME) || ::PersonalAccessToken.create!(
      user: user, name: TOKEN_NAME, scopes: [:api],
      organization_id: project.organization_id, expires_at: 30.days.from_now)
  end

  def seed_workspace_variables(workspace)
    # The second variable carries the empty value the encryptor allows, so both shapes are present.
    [{ key: VARIABLE_KEY, value: 'seeded' }, { key: "#{VARIABLE_KEY}_EMPTY", value: '' }].each do |attrs|
      next if ::RemoteDevelopment::WorkspaceVariable.exists?(workspace_id: workspace.id, key: attrs[:key])

      ::RemoteDevelopment::WorkspaceVariable.create!(
        workspace: workspace, project_id: workspace.project_id, user_provided: true,
        variable_type: ::RemoteDevelopment::Enums::WorkspaceVariable::ENVIRONMENT_TYPE, **attrs)
      print '.'
    end
  end

  def seed_workspace_agentk_state(workspace)
    return if ::RemoteDevelopment::WorkspaceAgentkState.exists?(workspace_id: workspace.id)

    ::RemoteDevelopment::WorkspaceAgentkState.create!(
      workspace: workspace, project_id: workspace.project_id,
      desired_config: [{ 'kind' => 'ConfigMap', 'metadata' => { 'name' => WORKSPACE_NAME } }])
    print '.'
  end

  def seed_runner_cost_setting
    runner = ::Ci::Runner.instance_type.order(:id).first
    return warn "\nSkipping runner cost setting seed: no instance runner available" if runner.nil?
    return if ::Ci::Minutes::CostSetting.exists?(runner_id: runner.id)

    ::Ci::Minutes::CostSetting.create!(
      runner: runner, standard_factor: 2.0, os_contribution_factor: 0.008, os_plan_factor: 0.5)
    print '.'
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating workspace and runner cost setting data"

  Gitlab::Seeder::WorkspacesAndRunnerCostSettings.new.seed!
end
