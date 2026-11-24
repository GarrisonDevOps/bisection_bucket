# frozen_string_literal: true

module Search
  module Zoekt
    class SelectionService
      attr_reader :max_batch_size

      ResourcePool = Struct.new(:enabled_namespaces, :nodes)

      PAID_CURSOR_CACHE_KEY = 'search/zoekt/selection_service/paid_without_replicas_cursor'
      ALL_CURSOR_CACHE_KEY = 'search/zoekt/selection_service/without_replicas_cursor'
      CURSOR_CACHE_TTL = 10.minutes

      def self.execute(**kwargs)
        new(**kwargs).execute
      end

      def initialize(max_batch_size: 128)
        @max_batch_size = max_batch_size
      end

      def execute
        namespaces = fetch_enabled_namespace_for_indexing
        nodes = fetch_available_nodes

        ResourcePool.new(namespaces, nodes)
      end

      private

      def fetch_enabled_namespace_for_indexing
        batch = fetch_paid_namespaces_without_replicas
        batch += fetch_namespaces_without_replicas(selected: batch) if batch.size < max_batch_size
        return batch if batch.size >= max_batch_size

        # Namespaces with no replica come first, so every namespace is searchable before any gets
        # an extra replica. This slow scan then catches the rest, such as too many or too few replicas.
        selected_ids = batch.to_set(&:id)
        ::Search::Zoekt::EnabledNamespace.with_rollout_allowed.each_batch_with_mismatched_replicas do |ns|
          next if selected_ids.include?(ns.id)

          batch << ns
          break if batch.size >= max_batch_size
        end

        batch
      end

      # Paid namespaces would otherwise wait behind thousands of trials enabled before them.
      def fetch_paid_namespaces_without_replicas
        return [] unless ::Gitlab::Saas.feature_available?(:exact_code_search)

        with_cursor(PAID_CURSOR_CACHE_KEY) do |after_id|
          ::Search::Zoekt::EnabledNamespace.with_rollout_allowed.with_paid_subscription
            .without_replicas(after_id: after_id).ordered_by_id.with_limit(max_batch_size).to_a
        end
      end

      def fetch_namespaces_without_replicas(selected:)
        with_cursor(ALL_CURSOR_CACHE_KEY) do |after_id|
          ::Search::Zoekt::EnabledNamespace.with_rollout_allowed.without_replicas(after_id: after_id)
            .excluding(*selected).ordered_by_id.with_limit(max_batch_size - selected.size).to_a
        end
      end

      # Stops just before the first match, so the re-enqueue check in RolloutService doesn't skip unprovisioned
      # namespaces. The key changes every CURSOR_CACHE_TTL, so rows passed over are rescanned from the start.
      def with_cursor(cache_key)
        key = [cache_key, Time.current.to_i / CURSOR_CACHE_TTL.to_i]
        max_id = ::Search::Zoekt::EnabledNamespace.maximum(:id).to_i
        namespaces = yield Rails.cache.read(key).to_i
        cursor = namespaces.any? ? namespaces.first.id - 1 : max_id
        Rails.cache.write(key, cursor, expires_in: CURSOR_CACHE_TTL)

        namespaces
      end

      def fetch_available_nodes
        nodes = ::Search::Zoekt::Node.available_for_search_indexing
        return nodes unless Feature.enabled?(:zoekt_node_eviction_safeguards, :instance)

        # A node that just evicted is still over the watermark until it has no index pending removal, so it
        # shouldn't take new namespaces in the meantime.
        cooldown_node_ids = ::Search::Zoekt::NodeEvictionState.cooldown_node_ids
        cooldown_node_ids.empty? ? nodes : nodes.id_not_in(cooldown_node_ids)
      end
    end
  end
end
