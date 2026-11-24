# frozen_string_literal: true

module Cd
  module Rollouts
    module WorkflowEvents
      class EnvironmentTransition
        def initialize(rollout, event)
          @rollout = rollout
          @event = event
        end

        def execute
          case event.type
          when WorkflowEventTypes::STAGE_STARTED, WorkflowEventTypes::STEP_STARTED
            transition(:start)
          when WorkflowEventTypes::STAGE_SUCCEEDED, WorkflowEventTypes::STEP_SUCCEEDED
            transition(:complete)
          when WorkflowEventTypes::STAGE_FAILED, WorkflowEventTypes::STEP_FAILED
            transition(:fail_environment)
          end
        end

        private

        attr_reader :rollout, :event

        def transition(state_event)
          return unless event.environment_name

          rollout_environment = rollout.rollout_environments.with_environment_name(event.environment_name).first

          return log_unmatched_environment unless rollout_environment

          # rubocop:disable GitlabSecurity/PublicSend -- state_event is one of the three symbols passed above, never request data
          rollout_environment.public_send(state_event)
          # rubocop:enable GitlabSecurity/PublicSend
        end

        def log_unmatched_environment
          Cd::Logger.info(
            message: 'Unmatched CD rollout workflow event environment',
            rollout_id: rollout.id,
            rollout_environment_name: event.environment_name
          )
        end
      end
    end
  end
end
