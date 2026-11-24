# frozen_string_literal: true

Gitlab::Seeder.quiet do
  Ai::DuoAgentPlatform::FunctionalVerificationRun::CHECK_TYPES.each_key.with_index(1) do |check_type, workflow_id|
    Ai::DuoAgentPlatform::FunctionalVerificationRun.create!(
      check_type: check_type,
      status: :passed,
      workflow_id: workflow_id
    )

    print '.'
  end
end
