# frozen_string_literal: true

module Search
  module Zoekt
    class LostNodeEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      idempotent!

      defer_on_database_health_signal :gitlab_main, [:zoekt_nodes, :zoekt_indices, :zoekt_repositories], 10.minutes

      BATCH_SIZE = 10_000

      def handle_event(event)
        return false unless Search::Zoekt::Node.marking_lost_enabled?

        node = Node.for_search.find_by_id(event.data[:zoekt_node_id])
        return unless node
        return unless node.lost?

        log_metadata = {}
        start_time = Time.current
        ApplicationRecord.transaction do
          node.lock!
          indices = node.indices
          unless indices.empty?
            count = 0
            Repository.for_zoekt_indices(indices).each_batch(of: BATCH_SIZE) { |batch| count += batch.delete_all }
            log_metadata[:deleted_repos_count] = count
            count = 0
            indices.each_batch(of: BATCH_SIZE) { |batch| count += batch.delete_all }
            log_metadata[:deleted_indices_count] = count
          end

          node.delete
        end
        log_metadata[:transaction_time] = Time.current - start_time
        log_hash_metadata_on_done(node_id: node.id, node_name: node[:metadata][:name], metadata: log_metadata)
      end
    end
  end
end
