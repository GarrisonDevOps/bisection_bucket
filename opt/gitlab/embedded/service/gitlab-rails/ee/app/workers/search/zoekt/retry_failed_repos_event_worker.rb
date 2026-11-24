# frozen_string_literal: true

module Search
  module Zoekt
    class RetryFailedReposEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      BATCH_SIZE = 100

      idempotent!

      defer_on_database_health_signal :gitlab_main, [:zoekt_repositories], 10.minutes

      def handle_event(_event)
        updated_rows = Repository.failed.limit(BATCH_SIZE)
          .update_all(state: :pending, retries_left: 1, updated_at: Time.current)
        log_extra_metadata_on_done(:repositories_updated_count, updated_rows)

        return if updated_rows < BATCH_SIZE

        Gitlab::EventStore.publish(RetryFailedReposEvent.build)
      end
    end
  end
end
