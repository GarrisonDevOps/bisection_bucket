# frozen_string_literal: true

module Search
  module Zoekt
    class TaskClaimExpiredEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      urgency :low
      idempotent!

      defer_on_database_health_signal :gitlab_main, [:zoekt_tasks], 10.minutes

      def handle_event(_event)
        result = Task.reset_expired_claims!
        log_extra_metadata_on_done(:tasks_with_expired_claim_count, result[:reaped])

        reemit_event(selected_count: result[:selected])
      end

      private

      def reemit_event(selected_count:)
        return if selected_count < Task::EXPIRED_CLAIM_BATCH_SIZE

        Gitlab::EventStore.publish(TaskClaimExpiredEvent.build)
      end
    end
  end
end
