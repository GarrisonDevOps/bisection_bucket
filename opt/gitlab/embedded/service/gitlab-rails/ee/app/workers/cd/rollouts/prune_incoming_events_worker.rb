# frozen_string_literal: true

module Cd
  module Rollouts
    # Deletes claimed workflow event callbacks (see Cd::Rollouts::ClaimWorkflowEventService)
    # once they're old enough that a redelivery of the same event is no longer plausible.
    # Rows are pruned regardless of status: a stuck `pending` row (its worker never ran or
    # crashed before marking it completed) is not retried, so keeping it around longer buys
    # nothing.
    class PruneIncomingEventsWorker
      include ApplicationWorker

      data_consistency :sticky

      # rubocop:disable Scalability/CronWorkerContext -- prunes globally, not scoped to a user/project/namespace
      include CronjobQueue

      # rubocop:enable Scalability/CronWorkerContext

      idempotent!
      feature_category :continuous_delivery

      CUTOFF = 60.days
      BATCH_SIZE = 1_000

      def perform
        loop do
          deleted = ::Cd::RolloutIncomingEvent.created_before(CUTOFF.ago).limit(BATCH_SIZE).delete_all
          break if deleted < BATCH_SIZE
        end
      end
    end
  end
end
