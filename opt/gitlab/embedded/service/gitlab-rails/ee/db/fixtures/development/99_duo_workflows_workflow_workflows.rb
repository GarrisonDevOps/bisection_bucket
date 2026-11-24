# frozen_string_literal: true

# Only RestartWorkflowService writes to this table, and nothing seeds the workflows it
# links, so this fixture creates both sessions itself.
Gitlab::Seeder.quiet do
  if Ai::DuoWorkflows::WorkflowWorkflow.exists?
    print '.'
    next
  end

  project = Project.not_mass_generated.first
  next warn "\nSkipping duo_workflows_workflow_workflows seeds: no project available" unless project

  user = project.creator

  # Stands in for the session a user restarted.
  source_workflow = FactoryBot.create(
    :duo_workflows_workflow,
    project: project,
    user: user,
    goal: 'Seeded Duo session, restarted below'
  )

  # Stands in for the session RestartWorkflowService created from it.
  new_workflow = FactoryBot.create(
    :duo_workflows_workflow,
    project: project,
    user: user,
    goal: source_workflow.goal,
    environment: source_workflow.environment
  )

  errors = Ai::DuoWorkflows::WorkflowWorkflow.ensure_link(
    workflow: new_workflow,
    artifact: source_workflow,
    link_type: :source
  )

  raise "Failed to link seeded workflows: #{errors.full_messages.to_sentence}" if errors.any?

  print '.'
end
