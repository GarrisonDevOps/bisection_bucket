# frozen_string_literal: true

module Search
  module Zoekt
    class IndexToEvictEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      idempotent!

      defer_on_database_health_signal :gitlab_main, [:zoekt_indices, :zoekt_replicas], 10.minutes

      BATCH_SIZE = 1000

      def handle_event(_event)
        indices = Search::Zoekt::Index.pending_eviction.ordered.limit(BATCH_SIZE)
        return unless indices.exists?

        log_metadata = {}
        replica_id_to_delete = indices.pluck(:zoekt_replica_id).compact # rubocop: disable CodeReuse/ActiveRecord -- Using pluck only
        ApplicationRecord.transaction do
          updated_count = Index.for_replica(replica_id_to_delete).update_all(state: :evicted, updated_at: Time.current)
          deleted_count = Replica.id_in(replica_id_to_delete).delete_all
          log_metadata[:replicas_deleted_count] = deleted_count
          log_metadata[:indices_updated_count] = updated_count
        end

        log_hash_metadata_on_done(log_metadata)
      end
    end
  end
end
