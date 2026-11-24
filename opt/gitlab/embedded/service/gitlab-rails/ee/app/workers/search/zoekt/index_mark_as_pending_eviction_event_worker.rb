# frozen_string_literal: true

module Search
  module Zoekt
    class IndexMarkAsPendingEvictionEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      idempotent!

      defer_on_database_health_signal :gitlab_main, [:zoekt_indices], 10.minutes

      BATCH_SIZE = 1000

      def handle_event(_event)
        indices = Search::Zoekt::Index.should_be_pending_eviction.limit(BATCH_SIZE)
        return unless indices.exists?

        updated_count = indices.update_all(state: :pending_eviction, updated_at: Time.current)

        log_extra_metadata_on_done(:indices_updated_count, updated_count)
      end
    end
  end
end
