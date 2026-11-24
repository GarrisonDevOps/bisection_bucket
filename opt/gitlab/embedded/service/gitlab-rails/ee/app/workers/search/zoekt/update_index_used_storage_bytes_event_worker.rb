# frozen_string_literal: true

module Search
  module Zoekt
    class UpdateIndexUsedStorageBytesEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      idempotent!
      defer_on_database_health_signal :gitlab_main, [:zoekt_indices], 10.minutes

      BATCH_SIZE = 1000

      def handle_event(_event)
        return unless ::Search::Zoekt.licensed_and_indexing_enabled?

        batch_update_indices
        reemit_event
      end

      private

      def batch_update_indices
        indices = Index
          .with_stale_used_storage_bytes_updated_at
          .ordered_by_used_storage_updated_at
          .limit(BATCH_SIZE)
          .preload_node_zoekt_enabled_namespace
          .to_a

        return if indices.empty?

        repository_sums = Repository.sum_size_bytes_by_index(indices.map(&:id))
        prefetch_node_reserved_bytes(indices)

        # Phase 1: compute all new values in-memory (sequential node-allocation logic preserved).
        # This replaces the previous approach of calling save! inside the loop, which fired
        # one SQL UPDATE per index (up to 1000 round-trips).
        updates = indices.map do |index|
          old_reserved = index.reserved_storage_bytes

          update_attrs = index.compute_storage_bytes_and_watermark_level(
            repository_size_sum: repository_sums.fetch(index.id, 0)
          )

          delta = index.reserved_storage_bytes - old_reserved
          index.node&.adjust_reserved_storage_bytes_cache(delta) unless delta == 0

          update_attrs
        end

        # Phase 2: persist all computed values in a single SQL UPDATE.
        Index.bulk_update_storage_bytes_and_watermark_level!(updates)
      end

      def prefetch_node_reserved_bytes(indices)
        node_ids = indices.filter_map(&:zoekt_node_id).uniq

        totals = Index.sum_reserved_storage_bytes_by_node(node_ids)
        nodes_by_id = indices.filter_map(&:node).uniq(&:id).index_by(&:id)

        totals.each do |node_id, total|
          nodes_by_id[node_id].reserved_storage_bytes_cache = total
        end
      end

      def reemit_event
        return unless Index.with_stale_used_storage_bytes_updated_at.exists?

        Gitlab::EventStore.publish(Search::Zoekt::UpdateIndexUsedStorageBytesEvent.new(data: {}))
      end
    end
  end
end
