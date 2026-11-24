# frozen_string_literal: true

module RedisCacheable # rubocop:todo Gitlab/BoundedContexts -- Same as RedisCacheable, see https://gitlab.com/gitlab-org/gitlab/-/work_items/638242
  # Reads the cached attributes of one record from Redis at most once.
  class CachedAttributesReader
    class << self
      # Fills all readers that are not loaded yet with one batched Redis read.
      def preload(readers)
        pending = readers.reject(&:loaded?)
        return if pending.empty?

        raw_values = read_multi(pending.map(&:key))

        pending.zip(raw_values) { |reader, raw| reader.load_raw(raw) }
      end

      private

      def read_multi(keys)
        Gitlab::Redis::Cache.with { |redis| read_multi_from(redis, keys) }
      end

      # On a cluster the keys are in different slots, so MGET is not possible.
      def read_multi_from(redis, keys)
        if Gitlab::Redis::ClusterUtil.cluster?(redis)
          Gitlab::Redis::ClusterUtil.batch_get(keys, redis)
        else
          Gitlab::Redis::ClusterUtil.batch_entries(keys) { |subset| mget(redis, subset) }
        end
      end

      def mget(redis, keys)
        Gitlab::Instrumentation::RedisClusterValidator.allow_cross_slot_commands do
          redis.mget(keys)
        end
      end
    end

    attr_reader :key

    def initialize(key)
      @key = key
      @attributes = nil
      @loaded = false
    end

    def attributes
      load_raw(read_from_redis) unless loaded?

      @attributes
    end

    def loaded?
      @loaded
    end

    def load_raw(raw)
      # rubocop:todo Gitlab/JsonSafeParse -- Same parse as RedisCacheable had, see https://gitlab.com/gitlab-org/gitlab/-/work_items/638242
      @attributes = raw && Gitlab::Json.parse(raw, symbolize_names: true)
      # rubocop:enable Gitlab/JsonSafeParse
      @loaded = true
    end

    private

    def read_from_redis
      Gitlab::Redis::Cache.with { |redis| redis.get(key) }
    end
  end
end
