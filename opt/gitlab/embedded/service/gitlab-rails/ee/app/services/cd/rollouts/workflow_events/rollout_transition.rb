# frozen_string_literal: true

module Cd
  module Rollouts
    module WorkflowEvents
      class RolloutTransition
        def initialize(rollout, event)
          @rollout = rollout
          @event = event
        end

        def execute
          case event.type
          when WorkflowEventTypes::ROLLOUT_SUCCEEDED
            rollout.complete
          when WorkflowEventTypes::STEP_STARTED
            open_gate if approval_step?
          when WorkflowEventTypes::APPROVAL_REQUESTED
            open_gate
          end

          transition_step
        end

        private

        attr_reader :rollout, :event

        def approval_step?
          event.step_type == ::Cd::RolloutStep::APPROVAL_STEP_TYPE
        end

        def open_gate
          rollout.with_lock do
            next if rollout.open_approval_gate? || rollout.state.in?(::Cd::Rollout::TERMINAL_STATES.map(&:to_s))

            rollout.rollout_transitions.create!(
              event: ::Cd::RolloutTransition::EVENT_REQUEST_APPROVAL,
              from_state: rollout.state,
              to_state: rollout.state,
              principal: 'system:autoflow',
              rollout_step: step,
              reason: event.reason
            )

            ActiveRecord.after_all_transactions_commit { GraphqlTriggers.cd_rollout_gate_updated(rollout) }
          end
        end

        def transition_step
          return unless event.step_path
          return log_unmatched_step unless step

          transitioned =
            case event.type
            when WorkflowEventTypes::STAGE_STARTED, WorkflowEventTypes::STEP_STARTED,
                 WorkflowEventTypes::APPROVAL_REQUESTED
              step.start
            when WorkflowEventTypes::STAGE_SUCCEEDED, WorkflowEventTypes::STEP_SUCCEEDED
              step.succeed
            when WorkflowEventTypes::STAGE_FAILED, WorkflowEventTypes::STEP_FAILED
              step.error = event.error
              step.fail_step
            end

          rollout.sync_state_from_steps! if transitioned
        end

        def log_unmatched_step
          Cd::Logger.info(
            message: 'Unmatched CD rollout workflow event step',
            rollout_id: rollout.id,
            rollout_step_path: event.step_path
          )
        end

        # Memoized so #open_gate and #transition_step share one lookup: both
        # act on the step named by the same triggering event. `||=` would not
        # cache a nil result (no step_path, or no matching step), so this
        # checks `defined?` instead to also memoize the "no step" case.
        def step
          return @step if defined?(@step)

          @step = event.step_path && rollout.rollout_steps.with_path(event.step_path).first
        end
      end
    end
  end
end
