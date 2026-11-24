# frozen_string_literal: true

# Nothing writes to this table yet (see https://gitlab.com/gitlab-org/gitlab/-/work_items/623178).
# This fixture exists so db:migrate:multi-version-upgrade has rows to exercise: one mid-walk,
# one between walks with the nullable columns left empty.
Gitlab::Seeder.quiet do
  root_namespace = Group.top_level.first
  next warn "\nSkipping ai_compliance_anthropic_sessions seeds: no top-level group available" unless root_namespace

  user = root_namespace.first_owner || User.first
  integration = Ai::Compliance::Anthropic::Integration.find_or_create_by!(namespace: root_namespace) do |record|
    record.api_key = "sk-ant-api01-#{SecureRandom.hex(8)}"
  end

  [
    { message_watermark: "clsm_#{SecureRandom.hex(8)}", walk_started_at: 10.minutes.ago },
    {}
  ].each do |walk_state|
    session_xid = "clls_#{SecureRandom.hex(8)}"
    governance_session = Ai::Governance::Session.create!(
      namespace: root_namespace,
      user: user,
      session_started_at: 30.minutes.ago,
      external_xid: session_xid,
      source: :claude_code_compliance_api,
      status: :running
    )

    Ai::Compliance::Anthropic::Session.create!(
      namespace: root_namespace,
      anthropic_integration: integration,
      ai_governance_session: governance_session,
      session_xid: session_xid,
      **walk_state
    )
  end

  print '.'
end
