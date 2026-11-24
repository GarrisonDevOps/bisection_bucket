# frozen_string_literal: true

module Ci
  module Runners
    # The runners whose runner managers reached ci_runner_manager_creation_ceiling, as last counted by
    # RunnerManagerCapService. Counting is too slow for the request path, so requests only look up this set.
    #
    # Each entry expires unless a later count renews it, so the set empties if the counting stops.
    class RunnerManagerCreationCeiling
      REDIS_KEY = 'ci:runners:runner_manager_creation_ceiling'
      # Three cron intervals, so that a delayed run doesn't let an entry expire.
      TTL = 30.minutes
      # The set only changes when the cron worker counts again.
      RETRY_AFTER = 10.minutes
      # Every listed runner is counted up to the ceiling on each run, so this keeps those counts within the run's time.
      # Far fewer runners are expected to reach the ceiling.
      MAX_RUNNERS = 100

      class << self
        # Fails open: when Redis is unavailable, runner manager creation is allowed.
        def reached?(runner)
          score = with_redis { |redis| redis.zscore(REDIS_KEY, runner.id.to_s) }

          score.present? && score > Time.current.to_f
        rescue ::Redis::BaseError, ::RedisClient::Error => e
          Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e)
          false
        end

        # Fails open like reached?, so that a Redis error doesn't stop the cap: recorded runners aren't counted again.
        def runner_ids
          with_redis do |redis|
            redis.zrangebyscore(REDIS_KEY, "(#{Time.current.to_f}", '+inf', limit: [0, MAX_RUNNERS])
          end.map(&:to_i)
        rescue ::Redis::BaseError, ::RedisClient::Error => e
          Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e)
          []
        end

        # On a Redis error the set isn't updated, and its entries expire.
        def record(reached_runner_ids:, cleared_runner_ids:)
          now = Time.current

          with_redis do |redis|
            redis.multi do |multi|
              multi.zremrangebyscore(REDIS_KEY, '-inf', now.to_f)
              multi.zrem(REDIS_KEY, cleared_runner_ids.map(&:to_s)) if cleared_runner_ids.any?

              if reached_runner_ids.any?
                expires_at = (now + TTL).to_f
                multi.zadd(REDIS_KEY, reached_runner_ids.map { |id| [expires_at, id.to_s] })
                multi.expire(REDIS_KEY, TTL.to_i)
              end
            end
          end
        rescue ::Redis::BaseError, ::RedisClient::Error => e
          Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e)
        end

        private

        def with_redis(&block)
          Gitlab::Redis::SharedState.with(&block) # rubocop:disable CodeReuse/ActiveRecord -- not ActiveRecord
        end
      end
    end
  end
end
