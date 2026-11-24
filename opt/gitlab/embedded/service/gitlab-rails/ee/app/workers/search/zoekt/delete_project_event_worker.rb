# frozen_string_literal: true

module Search
  module Zoekt
    class DeleteProjectEventWorker
      include ApplicationWorker
      include Search::Zoekt::EventWorker
      include Gitlab::EventStore::Subscriber
      prepend ::Geo::SkipSecondary

      data_consistency :delayed
      urgency :low
      idempotent!

      defer_on_database_health_signal :gitlab_main, [], 10.minutes

      def handle_event(event)
        return unless ::Search::Zoekt.licensed_and_indexing_enabled?

        Search::Zoekt.delete_async(event.data[:project_id], root_namespace_id: event.data[:root_namespace_id])
      end
    end
  end
end
