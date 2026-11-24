# frozen_string_literal: true

module ClickHouse
  module WriteBuffer
    extend Gitlab::Redis::BackwardsCompatibility

    BUFFER_KEY_PREFIX = 'clickhouse_write_buffer_'
    # Headroom above the normal backlog of the 2-minute drain. Events past it are
    # dropped and counted rather than left to grow Redis without bound.
    MAX_PENDING = 500_000
    # Only tables whose events can survive a dropped row. Audit events have no retry or
    # PostgreSQL fallback, so they stay uncapped for this rollout.
    CAPPED_TABLES = %w[ai_usage_events].freeze

    class << self
      def add(table_name, event_hash)
        return drop(table_name) if capped?(table_name) && pending(table_name) >= MAX_PENDING

        Gitlab::Redis::SharedState.with do |redis|
          redis.rpush(buffer_key(table_name), event_hash.to_json)
        end
      end

      def pending(table_name)
        Gitlab::Redis::SharedState.with do |redis|
          redis.llen(buffer_key(table_name)).to_i
        end
      end

      # Puts rows the worker already popped back after a failed insert; they are never dropped.
      def add_all(table_name, event_hashes)
        return if event_hashes.empty?

        Gitlab::Redis::SharedState.with do |redis|
          redis.rpush(buffer_key(table_name), event_hashes.map(&:to_json))
        end
      end

      def pop(table_name, limit)
        Array.wrap(lpop_with_limit(buffer_key(table_name), limit)).map do |hash|
          Gitlab::Json.parse(hash, symbolize_names: true)
        end
      end

      private

      def drop(table_name)
        dropped_counter.increment({ table: table_name })
        nil
      end

      def capped?(table_name)
        CAPPED_TABLES.include?(table_name.to_s) && Feature.enabled?(:analytics_write_buffer_protection, :instance)
      end

      def dropped_counter
        Gitlab::Metrics.counter(
          :gitlab_clickhouse_write_buffer_dropped_total,
          'Events dropped because a ClickHouse write buffer reached its cap'
        )
      end

      def buffer_key(table_name)
        "#{BUFFER_KEY_PREFIX}#{table_name}"
      end
    end
  end
end
