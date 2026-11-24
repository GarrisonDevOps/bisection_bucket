# frozen_string_literal: true

module Search
  module Zoekt
    class IndexMarkedAsReadyEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      idempotent!
      defer_on_database_health_signal :gitlab_main, [:zoekt_indices], 10.minutes

      BATCH_SIZE = 1000

      def handle_event(_event)
        indices = Index.initializing.with_all_finished_repositories.ordered.limit(BATCH_SIZE)
        return unless indices.exists?

        log_extra_metadata_on_done(:indices_ready_count, indices.update_all(state: :ready, updated_at: Time.current))
      end
    end
  end
end
