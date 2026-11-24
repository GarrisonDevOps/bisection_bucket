# frozen_string_literal: true

module Gitlab
  module SidekiqMiddleware
    module ConcurrencyLimit
      class LimitManager
        include Gitlab::Utils::StrongMemoize

        TTL = 30.minutes
        OVERRIDE_MAX_TTL = 1.day
        InvalidOverrideError = Class.new(StandardError)
        attr_reader :worker_name

        def initialize(worker_name:, prefix:)
          @worker_name = worker_name
          @prefix = prefix
        end

        # Pauses take precedence over overrides; overrides take precedence over adaptive limits.
        # Missing Redis values fall back to the worker default in this shard's runtime context.
        def current_limit
          return 0 if worker_klass.nil?

          effective_limit(default_limit)
        end

        # Enqueue processes use the destination shard's default without changing execution-time resolution.
        def enqueue_limit
          return 0 if worker_klass.nil?

          effective_limit(
            worker_klass.get_concurrency_limit(calculated_default: -> { EnqueueLimit.read(worker_klass) })
          )
        rescue ::Redis::BaseError => e
          Gitlab::ErrorTracking.track_exception(e, worker_class: worker_name)
          default_limit
        end

        # Adaptive calculations must never use an operator's override as their starting value.
        def adaptive_limit
          stored_adaptive_limit || default_limit
        end

        def override_active?
          with_redis { |r| !r.get(override_limit_key).nil? }
        end

        def set_override_limit!(value, ttl: TTL.to_i)
          unless worker_klass.is_a?(Class) && worker_klass.include?(ApplicationWorker)
            raise InvalidOverrideError, 'Unknown Sidekiq worker'
          end

          # The Redis key is built from worker_name, but readers build it from the class name.
          raise InvalidOverrideError, "Use the class name #{worker_klass.name}" unless worker_klass.name == worker_name

          if worker_name == 'ConcurrencyLimit::ResumeWorker'
            raise InvalidOverrideError, 'The deferred-job resumer cannot be limited'
          end

          if default_limit < 0 || worker_klass.configured_concurrency_limit.to_i < 0
            raise InvalidOverrideError, 'Worker is paused'
          end

          unless middleware_enabled?
            raise InvalidOverrideError, 'Concurrency limits are disabled by sidekiq_concurrency_limit_middleware'
          end

          if disabled_for_worker?
            raise InvalidOverrideError,
              "Concurrency limits are disabled for this worker by #{disable_flag_name}"
          end

          raise InvalidOverrideError, 'Limit must be a positive integer' unless value.is_a?(Integer) && value > 0

          unless ttl.is_a?(Integer) && ttl.between?(1, OVERRIDE_MAX_TTL.to_i)
            raise InvalidOverrideError, "TTL must be an integer between 1 and #{OVERRIDE_MAX_TTL.to_i} seconds"
          end

          with_redis { |r| r.set(override_limit_key, value, ex: ttl) }
          log_override('set', limit: value, ttl: ttl)
        end

        def clear_override_limit!
          with_redis { |r| r.del(override_limit_key) }
          log_override('reset')
        end

        def override_status
          value, ttl = with_redis do |r|
            r.pipelined do |pipeline|
              pipeline.get(override_limit_key)
              pipeline.ttl(override_limit_key)
            end
          end

          { limit: value&.to_i, ttl: ttl >= 0 ? ttl : nil }
        end

        def stored_adaptive_limit
          with_redis { |r| r.get(current_limit_key) }&.to_i
        end

        # Updates the current limit value in Redis
        # @param value [Integer] The new limit value to set
        def set_current_limit!(value)
          with_redis do |r|
            # An override may be set after the adaptive controller's initial check.
            r.eval(<<~LUA, keys: [override_limit_key, current_limit_key], argv: [value.to_i, TTL.to_i])
              if redis.call('EXISTS', KEYS[1]) == 1 then
                return 0
              end
              redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[2])
              return 1
            LUA
          end
        end

        private

        def effective_limit(limit)
          return limit if limit < 0
          # get_concurrency_limit returns 0 both when the flag is off and for unlimited workers.
          return 0 if limit == 0 && !middleware_enabled?

          override, value = with_redis { |r| r.mget(override_limit_key, current_limit_key) }
          (override || value)&.to_i || limit
        end

        def worker_klass
          worker_name.safe_constantize
        end
        strong_memoize_attr(:worker_klass)

        def default_limit
          worker_klass.respond_to?(:get_concurrency_limit) ? worker_klass.get_concurrency_limit : 0
        end

        def middleware_enabled?
          Feature.enabled?(:sidekiq_concurrency_limit_middleware, Feature.current_request, type: :ops)
        end

        def disable_flag_name
          "disable_sidekiq_concurrency_limit_middleware_#{worker_name}"
        end

        def disabled_for_worker?
          Feature.enabled?(
            :"disable_sidekiq_concurrency_limit_middleware_#{worker_name}", # rubocop:disable Gitlab/FeatureFlagKeyDynamic -- need to check against worker name dynamically
            Feature.current_request,
            type: :worker,
            default_enabled_if_undefined: false
          )
        end

        def log_override(action, limit: nil, ttl: nil)
          Gitlab::SidekiqLogging::ConcurrencyLimitLogger.instance.override_log(worker_name, action, limit, ttl)
        end

        def with_redis(&block)
          Gitlab::Redis::QueuesMetadata.with(&block) # rubocop:disable CodeReuse/ActiveRecord -- Not active record
        end

        def current_limit_key
          "#{@prefix}:{#{@worker_name.underscore}}:current_limit"
        end

        def override_limit_key
          "#{@prefix}:{#{@worker_name.underscore}}:override_limit"
        end
      end
    end
  end
end
