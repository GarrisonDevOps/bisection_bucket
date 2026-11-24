# frozen_string_literal: true

module Cd
  module Rollouts
    # Single source for the com.gitlab.cd.* event strings API::Cd::Rollouts and
    # every Cd::Rollouts::WorkflowEvents collaborator match against.
    module WorkflowEventTypes
      TOPIC = 'com.gitlab.cd.deployment'

      STAGE_STARTED = 'com.gitlab.cd.stage_started'
      STAGE_SUCCEEDED = 'com.gitlab.cd.stage_succeeded'
      STAGE_FAILED = 'com.gitlab.cd.stage_failed'
      STEP_STARTED = 'com.gitlab.cd.step_started'
      STEP_SUCCEEDED = 'com.gitlab.cd.step_succeeded'
      STEP_FAILED = 'com.gitlab.cd.step_failed'
      APPROVAL_REQUESTED = 'com.gitlab.cd.approval_requested'
      SERVICE_STARTED = 'com.gitlab.cd.service_started'
      SERVICE_SUCCEEDED = 'com.gitlab.cd.service_succeeded'
      SERVICE_FAILED = 'com.gitlab.cd.service_failed'
      ROLLOUT_SUCCEEDED = 'com.gitlab.cd.rollout_succeeded'
    end
  end
end
