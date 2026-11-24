# frozen_string_literal: true

module Search
  module Zoekt
    class OrphanedRepoEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      BATCH_SIZE = 1_000

      idempotent!

      defer_on_database_health_signal :gitlab_main, [:zoekt_repositories], 10.minutes

      def handle_event(_event)
        scope = Search::Zoekt::Repository.should_be_marked_as_orphaned
        return unless scope.exists?

        updated_rows = scope.limit(BATCH_SIZE).update_all(state: :orphaned, updated_at: Time.current)
        log_extra_metadata_on_done(:repositories_updated_count, updated_rows)

        reemit_event(updated_rows: updated_rows)
      end

      private

      def reemit_event(updated_rows:)
        return if updated_rows < BATCH_SIZE

        Gitlab::EventStore.publish(
          Search::Zoekt::OrphanedRepoEvent.new(data: {})
        )
      end
    end
  end
end
