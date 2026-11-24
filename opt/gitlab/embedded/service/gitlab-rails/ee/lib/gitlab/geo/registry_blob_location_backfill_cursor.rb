# frozen_string_literal: true

module Gitlab
  module Geo
    # Tracks one backfill pass over a replicator's registry table.
    #
    # Ranges are claimed with an atomic INCRBY, so concurrent jobs never share one.
    # If Redis is flushed, the backfill makes another pass, which is idempotent.
    class RegistryBlobLocationBackfillCursor
      KEY_PREFIX = 'geo:registry_blob_location_backfill'

      def initialize(replicable_name)
        @replicable_name = replicable_name
      end

      # @param [Integer] batch_size
      # @return [Range] the next range of registry IDs to process
      def claim_range(batch_size)
        last = with_redis { |redis| redis.incrby(cursor_key, batch_size) }

        (last - batch_size + 1)..last
      end

      # @return [Integer] the highest registry ID claimed so far
      def position
        with_redis { |redis| redis.get(cursor_key) }.to_i
      end

      def done?
        with_redis { |redis| redis.get(done_key) }.present?
      end

      def mark_done!
        with_redis { |redis| redis.set(done_key, '1') }
      end

      private

      def cursor_key
        "#{KEY_PREFIX}:#{@replicable_name}:cursor"
      end

      def done_key
        "#{KEY_PREFIX}:#{@replicable_name}:done"
      end

      def with_redis
        Gitlab::Redis::SharedState.with { |redis| yield redis }
      end
    end
  end
end
