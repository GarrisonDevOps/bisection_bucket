# frozen_string_literal: true

module Cd
  module Rollouts
    # Resolves an open approval gate on a rollout by writing the operator's
    # decision (approve or reject) to the Cd::RolloutTransition journal, then
    # pushing that decision into the paused AutoFlow workflow so it resumes
    # immediately instead of relying on the workflow polling the journal.
    #
    # The journal write is the source of truth and is never rolled back once
    # it succeeds; the push to AutoFlow is enqueued as a best-effort side
    # effect on top of it (see PushGateDecisionWorker/PushGateDecisionService).
    class ResolveGateService
      # Values reference Cd::RolloutTransition's canonical event constants so
      # the two can't drift out of sync on the literal event strings.
      EVENTS = {
        approved: Cd::RolloutTransition::EVENT_APPROVE,
        rejected: Cd::RolloutTransition::EVENT_REJECT
      }.freeze

      def initialize(rollout, current_user:, status:, resolution_reason: nil)
        @rollout = rollout
        @current_user = current_user
        @status = status.to_sym
        @resolution_reason = resolution_reason
      end

      def execute
        request_transition = rollout.open_gate_transition

        return error([_('Rollout has no open approval gate.')]) unless request_transition
        return error([_('Unknown gate status.')]) unless EVENTS.key?(status)

        transition = rollout.rollout_transitions.new(
          event: EVENTS.fetch(status),
          from_state: rollout.state,
          to_state: rollout.state,
          principal: principal,
          resolution_reason: resolution_reason
        )

        if transition.save
          # Enqueue only after commit (a job racing an open transaction could miss the transition
          # row and drop the push), and before the best-effort UI trigger, whose failure must not
          # skip the durability-critical enqueue.
          ActiveRecord.after_all_transactions_commit do
            ::Cd::Rollouts::PushGateDecisionWorker.perform_async(
              rollout.id, request_transition.id, transition.event, current_user.id
            )

            GraphqlTriggers.cd_rollout_gate_updated(rollout)
          end

          ServiceResponse.success(payload: { rollout_transition: transition })
        else
          error(transition.errors.full_messages)
        end
      end

      private

      attr_reader :rollout, :current_user, :status, :resolution_reason

      def principal
        "user:#{current_user.id}"
      end

      def error(messages)
        ServiceResponse.error(message: Array(messages), payload: { rollout_transition: nil })
      end
    end
  end
end
