# frozen_string_literal: true

# Seeds the vulnerability workflow table, which is empty in the upgrade stop dump, so migrations
# touching it were never exercised by db:migrate:multi-version-upgrade.
class Gitlab::Seeder::DependencySecurity # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  WORKFLOW_GOAL = 'Seeded vulnerability workflow'

  def seed!
    seed_triggered_workflow
  end

  private

  # No project in the dump carries both a finding and a workflow, and the model requires them to
  # share one, so the workflow is created in the finding's own project.
  def seed_triggered_workflow
    finding = Vulnerabilities::Finding.order(:id).first
    user = ::Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin
    return warn "\nSkipping triggered workflow seed: no finding or admin available" if finding.nil? || user.nil?
    return if Vulnerabilities::TriggeredWorkflow.exists?(vulnerability_occurrence_id: finding.id)

    workflow = Ai::DuoWorkflows::Workflow.find_by(project_id: finding.project_id, goal: WORKFLOW_GOAL) ||
      Ai::DuoWorkflows::Workflow.create!(user: user, project_id: finding.project_id, goal: WORKFLOW_GOAL)

    Vulnerabilities::TriggeredWorkflow.create!(
      vulnerability_occurrence: finding, workflow: workflow, workflow_name: :sast_fp_detection)
    print '.'
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating dependency security data"

  Gitlab::Seeder::DependencySecurity.new.seed!
end
