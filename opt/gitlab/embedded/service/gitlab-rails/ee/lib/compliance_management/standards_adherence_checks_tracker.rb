# frozen_string_literal: true

module ComplianceManagement
  class StandardsAdherenceChecksTracker
    include Gitlab::Utils::StrongMemoize

    attr_reader :group_id

    def initialize(group_id)
      @group_id = group_id
    end

    def redis_key
      "group:#{group_id}:progress_of_standards_adherence_checks"
    end

    def track_progress(total_checks)
      Gitlab::Redis::SharedState.with do |redis|
        redis.hset(redis_key, {
          'started_at' => Time.current.utc.to_s,
          'total_checks' => total_checks,
          'checks_completed' => 0
        })

        redis.expire(redis_key, 1.day.to_i)
      end
    end

    def already_enqueued?
      Gitlab::Redis::SharedState.with do |redis|
        redis.exists?(redis_key) # rubocop: disable CodeReuse/ActiveRecord -- this is a Redis method not ActiveRecord
      end
    end

    def update_progress
      return unless already_enqueued?

      Gitlab::Redis::SharedState.with do |redis|
        redis.hincrby(redis_key, 'checks_completed', 1)
      end
    end

    # Redis key 'group:<id>:progress_of_standards_adherence_checks' is a hash. It stores the timestamp when the
    # adherence scan was started for a group, total number of adherence checks and completed checks.
    # { started_at: <timestamp when the adherence scan was started for that group>,
    # total_checks: <number of projects in that group multiplied by number of checks>,
    # checks_completed: <total checks completed> }
    # The fields and values look like:
    # { "started_at"=>"2024-01-09 06:27:01 UTC", "total_checks"=>"15", "checks_completed"=>"0" }
    # @return [Hash]
    def progress
      Gitlab::Redis::SharedState.with do |redis|
        redis.hgetall(redis_key).transform_keys(&:to_sym)
      end
    end
  end
end
