# frozen_string_literal: true

Gitlab::Seeder.quiet do
  if Ai::DuoWorkflows::SessionFile.exists?
    print '.'
    next
  end

  project = Project.not_mass_generated.first
  next warn "\nSkipping duo_workflows_session_files seeds: no project available" unless project

  workflow = FactoryBot.create(
    :duo_workflows_workflow,
    project: project,
    user: project.creator,
    goal: 'Seeded Duo session with an attached image'
  )

  FactoryBot.create(:duo_workflows_session_file, workflow: workflow)

  print '.'
end
