# frozen_string_literal: true

module Search
  module Zoekt
    class RepoToIndexEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      idempotent!

      defer_on_database_health_signal :gitlab_main, [:zoekt_repositories, :zoekt_tasks], 10.minutes

      BATCH_SIZE = 500

      def handle_event(_event)
        return false unless ::Search::Zoekt.licensed_and_indexing_enabled?

        Repository.should_be_indexed.limit(BATCH_SIZE).create_bulk_tasks
        reemit_event
      end

      private

      def reemit_event
        return unless Repository.should_be_indexed.exists?

        Gitlab::EventStore.publish(Search::Zoekt::RepoToIndexEvent.new(data: {}))
      end
    end
  end
end
