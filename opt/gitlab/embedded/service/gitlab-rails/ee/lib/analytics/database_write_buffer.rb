# frozen_string_literal: true

# This class is used to put all writes to a buffer to avoid individual frequent writes
# and offload main DB.
# It's used mainly for frequent events like code suggestions telemetry.
module Analytics
  class DatabaseWriteBuffer
    include Gitlab::Redis::BackwardsCompatibility

    BUFFER_KEY_POSTFIX = "_db_write_buffer"
    # Headroom above the normal backlog of a periodic drain. Rows past it are dropped
    # and counted rather than left to grow Redis without bound.
    MAX_PENDING = 500_000

    def initialize(buffer_key:)
      @buffer_key = buffer_key
    end

    # Adds one or many hashes to the buffer
    def add(attributes)
      rows = Array.wrap(attributes)
      rows = drop_rows_past_cap(rows) if cap_enabled?

      push(rows)
    end

    # Puts rows the worker already popped back after a failed upsert; the cap applies only to new admissions.
    def requeue(attributes)
      push(Array.wrap(attributes))
    end

    # Pops X hashes from the buffer
    def pop(limit)
      Array.wrap(lpop_with_limit(buffer_key, limit)).map { |hash| Gitlab::Json.safe_parse(hash) }
    end

    # Number of hashes waiting in the buffer
    def pending
      Gitlab::Redis::SharedState.with do |redis|
        redis.llen(buffer_key).to_i
      end
    end

    private

    def push(rows)
      return if rows.empty?

      Gitlab::Redis::SharedState.with do |redis|
        redis.rpush(buffer_key, rows.map(&:to_json))
      end
    end

    def drop_rows_past_cap(rows)
      overflow = rows.size - [self.class::MAX_PENDING - pending, 0].max
      return rows if overflow <= 0

      dropped_counter.increment({ buffer: @buffer_key }, overflow)
      rows.first(rows.size - overflow)
    end

    def cap_enabled?
      Feature.enabled?(:analytics_write_buffer_protection, :instance)
    end

    def dropped_counter
      Gitlab::Metrics.counter(
        :gitlab_database_write_buffer_dropped_total,
        'Rows dropped because a PostgreSQL write buffer reached its cap'
      )
    end

    def buffer_key
      @buffer_key + BUFFER_KEY_POSTFIX
    end
  end
end
