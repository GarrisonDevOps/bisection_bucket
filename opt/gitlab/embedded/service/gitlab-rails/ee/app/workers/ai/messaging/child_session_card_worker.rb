# frozen_string_literal: true

module Ai
  module Messaging
    # Shows a session delegated from a messaging session (via start_flow) on the
    # parent's surface: once when it is created, then on its checkpoints, debounced
    # per session like ProgressDeliveryWorker. Its outcome is delivered by
    # CallbackWorker, which also renders the card's final state.
    # rubocop:disable Sidekiq/EnforceDatabaseHealthSignalDeferral -- a progress frame is stale by the time a deferral returns it
    class ChildSessionCardWorker
      include ApplicationWorker

      # Slower than ProgressDeliveryWorker's: the card is background work next to the
      # parent's answer, and every edit spends the channel's rate limit.
      DEBOUNCE_INTERVAL = 5.seconds

      feature_category :duo_agent_platform
      # The child was created just before this was enqueued.
      data_consistency :sticky
      urgency :low
      # Same load-bearing dedup as ProgressDeliveryWorker: scheduled jobs collapse, and a
      # checkpoint arriving mid-render reschedules once so the trailing frame still ships.
      deduplicate :until_executed, including_scheduled: true, if_deduplicated: :reschedule_once
      concurrency_limit -> { 200 }
      idempotent!
      worker_has_external_dependencies!

      def perform(workflow_id)
        child = ::Ai::DuoWorkflows::Workflow.find_by_id(workflow_id)
        return unless child
        # The outcome renders the final card.
        return if child.status_terminal?

        # Best effort: the next checkpoint or the outcome renders the card if this one never landed.
        ::Ai::Messaging::ChildSession.from_workflow(child)&.render_card
      end
    end
    # rubocop:enable Sidekiq/EnforceDatabaseHealthSignalDeferral
  end
end
