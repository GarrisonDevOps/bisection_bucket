# frozen_string_literal: true

module Gitlab
  module SidekiqMiddleware
    module ConcurrencyLimit
      class EnqueueLimit
        DEFAULT_TTL = Gitlab::Metrics::Samplers::ConcurrencyLimitSampler::LEASE_TIMEOUT +
          Gitlab::Metrics::Samplers::ConcurrencyLimitSampler::DEFAULT_SAMPLING_INTERVAL_SECONDS
        CACHE_TTL = 1.second
        CACHE = Concurrent::Map.new
        CacheEntry = Struct.new(:value, :expires_at)

        # @return [Boolean] whether this worker opted into shared enqueue defaults
        def self.enabled_for?(worker)
          return false unless worker.respond_to?(:configured_concurrency_limit)

          Feature.enabled?(
            :"sidekiq_concurrency_limit_enqueue_#{worker.name}", # rubocop:disable Gitlab/FeatureFlagKeyDynamic -- Per-worker enqueue rollout
            :instance, type: :worker, default_enabled_if_undefined: false
          )
        end

        # Only the Sidekiq process serving this queue knows its capacity; never publish Puma's zero default.
        # @return [void]
        def self.publish(worker, limit)
          return unless Gitlab::Runtime.sidekiq? && enabled_for?(worker)
          return unless worker.configured_concurrency_limit.nil?

          return unless ENV.fetch('GITLAB_SIDEKIQ_MAX_REPLICAS', '0').to_i > 0 &&
            ENV.fetch('SIDEKIQ_CONCURRENCY', '0').to_i > 0

          queue = worker.queue
          return unless Sidekiq.default_configuration.queues.include?(queue)

          destination, = Gitlab::SidekiqSharding::Router.get_shard_instance(worker.get_sidekiq_options['store'])
          # rubocop:disable Cop/RedisQueueUsage -- Reading the shard-name constant does not access queue Redis.
          current_shard = ENV.fetch('SIDEKIQ_SHARD_NAME', Gitlab::Redis::Queues::SIDEKIQ_MAIN_SHARD_INSTANCE_NAME)
          # rubocop:enable Cop/RedisQueueUsage
          return unless destination == current_shard

          Gitlab::Redis::QueuesMetadata.with { |redis| redis.set(key(worker), limit, ex: DEFAULT_TTL.to_i) }
          nil
        rescue ::Redis::BaseError => e
          Gitlab::ErrorTracking.track_exception(e, worker_class: worker.name)
          nil
        end

        # Missing and failed publications share the same short expiry as successful reads.
        # @return [Integer, nil] the published default, or nil when no fresh publication is available
        def self.read(worker)
          cache_key = key(worker)
          now = ::Gitlab::Metrics::System.monotonic_time
          entry = CACHE[cache_key]
          return entry.value if entry && entry.expires_at > now

          value = begin
            Gitlab::Redis::QueuesMetadata.with { |redis| redis.get(cache_key) }&.to_i
          rescue ::Redis::BaseError => e
            Gitlab::ErrorTracking.track_exception(e, worker_class: worker.name)
            nil
          end

          CACHE[cache_key] = CacheEntry.new(value, now + CACHE_TTL.to_i)
          value
        end

        # Routing is part of the key so a moved worker cannot reuse its old queue's published default.
        def self.key(worker)
          destination, = Gitlab::SidekiqSharding::Router.get_shard_instance(worker.get_sidekiq_options['store'])
          "#{ConcurrencyLimitService::REDIS_KEY_PREFIX}:{#{worker.name.underscore}}:default_limit:" \
            "#{worker.queue}:#{destination}"
        end
        private_class_method :key
      end
    end
  end
end
