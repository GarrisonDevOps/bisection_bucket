# frozen_string_literal: true

module Cd
  module Rollouts
    class ProcessWorkflowEventWorker
      include ApplicationWorker

      data_consistency :sticky

      idempotent!
      feature_category :continuous_delivery

      def perform(event_id, params)
        event = ::Cd::RolloutIncomingEvent.find_by_id(event_id)
        return if event.nil? || event.completed?

        ::Cd::Rollouts::ProcessWorkflowEventService.new(
          event.rollout, params: params.deep_symbolize_keys, incoming_event: event
        ).execute
      end
    end
  end
end
