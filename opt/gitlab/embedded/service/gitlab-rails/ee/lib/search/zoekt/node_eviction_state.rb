# frozen_string_literal: true

module Search
  module Zoekt
    # Remembers node-level eviction across scheduling runs: since when a node has been over the high
    # watermark, and which nodes evicted recently and are still freeing that space.
    class NodeEvictionState
      OVER_WATERMARK_KEY_PREFIX = 'search:zoekt:node_eviction:over_watermark_since'
      COOLDOWN_KEY = 'search:zoekt:node_eviction:cooldown'
      # Refreshed on every check while the node stays over the watermark, so a node that stops being
      # checked, for example because it went offline, starts a new period when it is seen over it again.
      OVER_WATERMARK_TTL = 1.hour
      COOLDOWN_TTL = 12.hours

      class << self
        # Records that the node is over the high watermark, keeping the time it was first seen over it.
        #
        # @param node [Search::Zoekt::Node]
        # @return [Time] when the node was first seen over the high watermark
        def record_over_watermark(node)
          now = Time.current.to_i
          key = over_watermark_key(node)

          first_seen = with_redis do |redis|
            redis.multi do |multi|
              multi.set(key, now, ex: OVER_WATERMARK_TTL.to_i, nx: true)
              multi.expire(key, OVER_WATERMARK_TTL.to_i)
              multi.get(key)
            end.last
          end

          Time.zone.at((first_seen || now).to_i)
        end

        # @param node [Search::Zoekt::Node]
        # @return [void]
        def clear_over_watermark(node)
          with_redis { |redis| redis.del(over_watermark_key(node)) }

          nil
        end

        # Starts a cooldown for a node that just evicted. It also clears the node's over-watermark
        # time, so another eviction needs the node to stay over the watermark again.
        #
        # @param node [Search::Zoekt::Node]
        # @return [void]
        def start_cooldown(node)
          with_redis do |redis|
            redis.zadd(COOLDOWN_KEY, COOLDOWN_TTL.from_now.to_i, node.id)
            redis.expire(COOLDOWN_KEY, COOLDOWN_TTL.to_i)
          end

          clear_over_watermark(node)
        end

        # @param node [Search::Zoekt::Node]
        # @return [void]
        def end_cooldown(node)
          with_redis { |redis| redis.zrem(COOLDOWN_KEY, node.id) }

          nil
        end

        # @return [Array<Integer>] IDs of nodes whose cooldown has not expired
        def cooldown_node_ids
          with_redis do |redis|
            redis.zremrangebyscore(COOLDOWN_KEY, '-inf', Time.current.to_i)
            redis.zrange(COOLDOWN_KEY, 0, -1).map(&:to_i)
          end
        end

        private

        def over_watermark_key(node)
          "#{OVER_WATERMARK_KEY_PREFIX}:#{node.id}"
        end

        def with_redis
          Gitlab::Redis::SharedState.with { |redis| yield redis }
        end
      end
    end
  end
end
