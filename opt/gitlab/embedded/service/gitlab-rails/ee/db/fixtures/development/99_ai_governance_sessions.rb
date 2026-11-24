# frozen_string_literal: true

# Nothing else writes to this table yet (see https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256344).
# This fixture exists purely so db:migrate:multi-version-upgrade has a row to exercise.
Gitlab::Seeder.quiet do
  project = Project.first
  namespace = project.project_namespace
  user = project.creator

  # Duo-sourced row: linked to a workflow, no external_xid, still running.
  Ai::Governance::Session.create!(
    namespace: namespace,
    user: user,
    session_started_at: 30.minutes.ago,
    workflow_id: SecureRandom.random_number(1_000_000),
    source: :gitlab_duo,
    status: :running
  )

  # External-agent-sourced row: identified by external_xid, no workflow_id, already finished.
  Ai::Governance::Session.create!(
    namespace: namespace,
    project: project,
    user: user,
    session_started_at: 5.minutes.ago,
    session_finished_at: Time.current,
    external_xid: "clls_#{SecureRandom.hex(8)}",
    source: :claude_code_compliance_api,
    status: :finished,
    agent_type: 'claude_code',
    flow_type: 'software_development'
  )

  print '.'
end
