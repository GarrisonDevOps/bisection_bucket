# frozen_string_literal: true

module Analytics
  # Stores last attributes set for each `user_id` in Redis hash.
  class AiUserMetricsDatabaseWriteBuffer < DatabaseWriteBuffer
    # One hash replaces what is buffered for that user. The hash is bounded by distinct users, not capped.
    def add(attributes)
      Gitlab::Redis::SharedState.with do |redis|
        redis.hset(buffer_key, user_key(attributes), attributes.to_json)
      end
    end

    # A failed batch being put back must not overwrite a value tracked since the pop: that one is newer.
    def requeue(attributes)
      Gitlab::Redis::SharedState.with do |redis|
        redis.pipelined do |pipeline|
          attributes.each { |attrs| pipeline.hsetnx(buffer_key, user_key(attrs), attrs.to_json) }
        end
      end
    end

    def pending
      Gitlab::Redis::SharedState.with do |redis|
        redis.hlen(buffer_key).to_i
      end
    end

    def pop(limit)
      Gitlab::Redis::SharedState.with do |redis|
        keys = redis.hkeys(buffer_key)[0..(limit - 1)]

        next [] if keys.empty?

        attributes, _deletes = redis.pipelined do |pipeline|
          pipeline.hmget(buffer_key, *keys)
          pipeline.hdel(buffer_key, keys)
        end

        attributes.compact.map { |attrs| Gitlab::Json.safe_parse(attrs) }
      end
    end

    private

    # Buffered hashes come back from Redis with string keys.
    def user_key(attrs)
      (attrs[:user_id] || attrs['user_id']).to_s
    end
  end
end
