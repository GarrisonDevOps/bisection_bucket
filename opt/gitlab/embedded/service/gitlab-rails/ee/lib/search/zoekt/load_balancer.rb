# frozen_string_literal: true

module Search
  module Zoekt
    class LoadBalancer
      CACHE_EXPIRY = 300

      def self.distribution(nodes = nil)
        nodes ||= Node.searchable
        new(nodes).distribution
      end

      attr_reader :nodes

      def initialize(nodes)
        raise ArgumentError, 'no nodes available for zoekt load balancer' if nodes.empty?

        @nodes = nodes
      end

      def distribution
        with_redis do |redis|
          keys = nodes.map { |node| node_key(node) }
          values = redis.mget(*keys)

          nodes.zip(values).map do |node, value|
            {
              node_id: node.id,
              current_load: value.to_f
            }
          end
        end
      end

      def reset!
        with_redis do |redis|
          nodes.each do |node|
            redis.del(node_key(node))
          end
        end
      end

      def pick
        return if nodes.empty?
        return nodes.first if nodes.size == 1

        with_redis do |redis|
          keys = nodes.map { |node| node_key(node) }
          values = redis.mget(*keys)

          # Select node with lowest load
          nodes.zip(values).min_by { |_node, value| value.to_f }.first
        end
      end

      def increase_load(node, weight: 1)
        # Increase by weight (heavy queries count more)
        with_redis do |redis|
          key = node_key(node)
          redis.incrbyfloat(key, weight)

          # Set expiry only if it doesn't already have one to avoid resetting TTL
          # Check if key has a TTL (-1 means no expiry, -2 means key doesn't exist)
          redis.expire(key, CACHE_EXPIRY) if redis.ttl(key) < 0
        end
      end

      def decrease_load(node, weight: 1)
        # Reduce load when query completes
        with_redis do |redis|
          new_value = redis.incrbyfloat(node_key(node), -weight)

          # Clean up if load goes to 0 or negative (due to floating point or errors)
          redis.del(node_key(node)) if new_value <= 0
        end
      end

      private

      def node_key(node)
        # Use hash tags to ensure all keys hash to the same Redis Cluster slot
        # This allows MGET to work in Redis Cluster mode
        "zoekt:{load_balancer}:node:#{node.id}"
      end

      def with_redis(&block)
        Gitlab::Redis::Cache.with(&block) # rubocop:disable CodeReuse/ActiveRecord -- N/A
      end
    end
  end
end
