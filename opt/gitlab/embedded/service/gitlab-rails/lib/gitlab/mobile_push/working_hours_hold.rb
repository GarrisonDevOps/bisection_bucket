# frozen_string_literal: true

module Gitlab
  module MobilePush
    # Users whose mobile pushes are paused outside their working hours, scored
    # with the moment their window next opens. One Redis sorted set is all the
    # state: the summary carries no count, and user_preferences must not take
    # a write per skipped push.
    class WorkingHoursHold
      RESUME_SET = 'mobile_push:working_hours:resume'
      # Resume times lie within a week, so the set outlives the latest one. A
      # sender down for longer would only find summaries too stale to send.
      RESUME_SET_TTL = 8.days

      class << self
        # Recording again moves the user to the new resume time.
        def record(user_id, resume_at)
          Gitlab::Redis::SharedState.with do |redis|
            redis.multi do |multi|
              multi.zadd(RESUME_SET, resume_at.to_i, user_id)
              multi.expire(RESUME_SET, RESUME_SET_TTL.to_i)
            end
          end
        end

        # User ids whose window has opened by `now`, at most `limit`.
        def due_user_ids(now, limit:)
          Gitlab::Redis::SharedState.with do |redis|
            redis.zrangebyscore(RESUME_SET, 0, now.to_i, limit: [0, limit]).map(&:to_i)
          end
        end

        # Removes the user from the wake-up list. False when another run
        # claimed them first, so two overlapping runs cannot both send.
        def claim(user_id)
          Gitlab::Redis::SharedState.with do |redis|
            removed = redis.zrem(RESUME_SET, user_id)
            removed == true || removed == 1
          end
        end
      end
    end
  end
end
