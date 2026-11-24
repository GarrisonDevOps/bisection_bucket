# frozen_string_literal: true

module Cd
  module Rollouts
    # Entry point for a flow-graph event from the CD orchestrator. Delegates to
    # the WorkflowEvents collaborator owning each resource the event may name;
    # each ignores event types it doesn't own, so calling all three is cheap.
    class ProcessWorkflowEventService
      # incoming_event is the Cd::RolloutIncomingEvent claim this call is processing, if any
      # (see Cd::Rollouts::ProcessWorkflowEventWorker); marked completed in the same
      # transaction as the event's own writes, so a failure here leaves it pending
      # rather than falsely marking a swallowed error as done.
      def initialize(rollout, params:, incoming_event: nil)
        @rollout = rollout
        @params = params
        @incoming_event = incoming_event
      end

      def execute
        event = WorkflowEvent.new(params)

        ::Cd::Rollout.transaction do
          WorkflowEvents::ChannelTokens.new(rollout, event).execute
          WorkflowEvents::EnvironmentTransition.new(rollout, event).execute
          WorkflowEvents::DeploymentTransition.new(rollout, event).execute
          WorkflowEvents::RolloutTransition.new(rollout, event).execute
          incoming_event&.completed!
        end

        ServiceResponse.success(payload: { rollout: rollout })
      rescue ActiveRecord::RecordInvalid, ActiveRecord::RecordNotUnique, ArgumentError => e
        Gitlab::ErrorTracking.track_exception(e, rollout_id: rollout.id)

        ServiceResponse.error(message: _('Unable to process rollout workflow event.'), payload: { rollout: rollout })
      end

      private

      attr_reader :rollout, :params, :incoming_event
    end
  end
end
