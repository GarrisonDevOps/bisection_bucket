# frozen_string_literal: true

module Search
  module Zoekt
    class NodeWithNegativeUnclaimedStorageEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      idempotent!

      defer_on_database_health_signal :gitlab_main, [:zoekt_indices], 10.minutes

      MAX_INDICES_TO_EVICT = 1_000

      def handle_event(event)
        return unless ::Search::Zoekt.licensed_and_indexing_enabled?

        node_ids = event.data[:node_ids]

        return if node_ids.empty?

        Search::Zoekt::Node.negative_unclaimed_storage_bytes.id_in(node_ids).find_each do |node|
          unclaimed_storage_bytes = node.unclaimed_storage_bytes
          next unless unclaimed_storage_bytes < 0

          best_fit = Feature.enabled?(:zoekt_negative_storage_eviction_best_fit, :instance)

          # Reservations run ahead of disk usage by design, so only evict once the disk itself is filling up.
          if best_fit && !node.watermark_exceeded_high?
            logger.info(build_structured_payload(
              message: 'Skipping node with negative unclaimed storage bytes below the high watermark',
              'zoekt.node_id': node.id,
              'zoekt.unclaimed_storage_bytes': unclaimed_storage_bytes))

            next
          end

          logger.info(build_structured_payload(
            message: 'Processing node with negative unclaimed storage bytes',
            'zoekt.node_id': node.id,
            'zoekt.unclaimed_storage_bytes': unclaimed_storage_bytes))

          index_ids_to_evict = if best_fit
                                 best_fit_index_ids(node, unclaimed_storage_bytes.abs)
                               else
                                 lowest_id_index_ids(node, unclaimed_storage_bytes.abs)
                               end

          indices = node.indices.id_in(index_ids_to_evict).limit(MAX_INDICES_TO_EVICT)
          updated_count = indices.update_all(state: :pending_eviction, updated_at: Time.current)

          log_extra_metadata_on_done(:indices_updated_count, updated_count)
        end
      end

      private

      def lowest_id_index_ids(node, bytes_to_free)
        total_reserved_bytes = 0
        index_ids_to_evict = []

        node.indices.not_pending_eviction.find_each do |index|
          total_reserved_bytes += index.reserved_storage_bytes if index.reserved_storage_bytes > 0

          index_ids_to_evict << index.id

          break if total_reserved_bytes >= bytes_to_free || index_ids_to_evict.size >= MAX_INDICES_TO_EVICT
        end

        index_ids_to_evict
      end

      # The smallest index that frees enough on its own disrupts one namespace and frees the least
      # extra. Without one, largest first frees enough with the fewest namespaces.
      def best_fit_index_ids(node, bytes_to_free)
        best_fit_id = node.indices.smallest_ready_id_reserving_at_least(bytes_to_free)
        return [best_fit_id] if best_fit_id

        total_reserved_bytes = 0
        node.indices.largest_ready_reservations(limit: MAX_INDICES_TO_EVICT)
          .take_while do |_id, reserved_storage_bytes|
            next false if total_reserved_bytes >= bytes_to_free

            total_reserved_bytes += reserved_storage_bytes
          end.map(&:first)
      end
    end
  end
end
