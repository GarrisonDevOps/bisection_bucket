# frozen_string_literal: true

module Search
  module Zoekt
    class TooManyReplicasEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      idempotent!
      defer_on_database_health_signal :gitlab_main, [], 10.minutes
      sidekiq_options retry: true

      BATCH_SIZE = 100

      def handle_event(_event); end
    end
  end
end
