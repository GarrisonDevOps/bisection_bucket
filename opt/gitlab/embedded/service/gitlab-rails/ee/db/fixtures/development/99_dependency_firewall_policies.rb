# frozen_string_literal: true

class Gitlab::Seeder::DependencyFirewallPolicies # rubocop:disable Style/ClassAndModuleChildren -- this is a seed script
  def initialize(project: nil)
    @project = project || Project.not_mass_generated.sample(1).first
  end

  def seed!
    unless ::Security::DependencyFirewall::Availability.access_enabled?(@project)
      puts 'Dependency Firewall feature flag is disabled, skipping...'
      return
    end

    puts "Seeding dependency firewall security policy in project #{@project.full_path} (#{@project.id})"

    current_user = Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin

    result = Gitlab::ExclusiveLease.skipping_transaction_check do
      Sidekiq::Worker.skipping_transaction_check do
        ::Security::SecurityOrchestrationPolicies::ProjectCreateService
          .new(container: @project, current_user: current_user)
          .execute
      end
    end

    if result[:status] == :error
      puts "Failed to create security policy project: #{result[:message]}"
      return
    end

    policy_project = result[:policy_project]
    policy_project.add_owner(current_user)
    policy_configuration = @project.reset.security_orchestration_policy_configuration

    # Persist project and namespace on DB so Gitaly's pre-receive hook can see them
    Project.connection.commit_db_transaction
    Project.connection.begin_db_transaction

    policy_yaml = <<~YAML
      ---
      vulnerability_management_policy:
      - name: Vuln Policy 3
        description: ''
        enabled: true
        rules:
        - type: no_longer_detected
          scanners: []
          severity_levels: []
        actions:
        - type: auto_resolve
      dependency_firewall_policy:
      - name: DFWPolicy3
        description: ''
        enabled: true
        enforcement_type: enforced
        rules:
        - type: license
          allowed:
          - name: NIST License
          exceptions:
          - purl: pkg:npm/my-internal-lib3
        - type: license
          allowed:
          - name: MIT License
          exceptions:
          - purl: pkg:npm/my-internal-lib4
        - type: license
          allowed:
          - name: Apache 2.0 License
          exceptions:
          - purl: pkg:npm/my-internal-lib5
        bypass_settings:
          users:
          - id: 1
    YAML

    default_branch = policy_project.default_branch_or_main
    policy_path = Security::OrchestrationPolicyConfiguration::POLICY_PATH

    Gitlab::ExclusiveLease.skipping_transaction_check do
      Sidekiq::Worker.skipping_transaction_check do
        allow_maintainers_to_push(policy_project, default_branch, current_user)

        policy_project.repository.create_file(
          current_user,
          policy_path,
          policy_yaml,
          message: 'Add security policy',
          branch_name: default_branch
        )

        Security::PersistSecurityPoliciesWorker.perform_sync(
          policy_configuration.id,
          { 'sync_reason' => 'force_resync' }
        )
      end
    end
  end

  private

  def allow_maintainers_to_push(project, branch_name, user)
    project.protected_branches.where(name: branch_name).find_each do |protected_branch|
      ProtectedBranches::UpdateService.new(
        project,
        user,
        push_access_levels_attributes: [{ access_level: Gitlab::Access::MAINTAINER }]
      ).execute(protected_branch, skip_authorization: true)
    end
  end
end

Gitlab::Seeder.quiet do
  project_id = ENV['PROJECT_ID']
  project = Project.find(project_id) if project_id

  Gitlab::Seeder::DependencyFirewallPolicies.new(project: project).seed!
end
