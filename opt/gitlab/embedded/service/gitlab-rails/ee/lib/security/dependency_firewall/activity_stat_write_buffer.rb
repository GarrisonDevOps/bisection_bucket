# frozen_string_literal: true

module Security
  module DependencyFirewall
    # Two-phase drain, as Gitlab::Counters::BufferedCounter; at-least-once, no TTL on the data-bearing keys.
    class ActivityStatWriteBuffer < ::Analytics::DatabaseWriteBuffer
      SEPARATOR = ':'

      LUA_STAGE_SCRIPT = <<~LUA
        local live, staged = KEYS[1], KEYS[2]
        local entries = redis.call('HGETALL', live)
        for i = 1, #entries, 2 do
          redis.call('HINCRBY', staged, entries[i], entries[i + 1])
        end
        redis.call('DEL', live)
        -- clear any TTL a previously deployed revision left on the staged key
        redis.call('PERSIST', staged)
      LUA

      LUA_REMOVE_STAGED_SCRIPT = <<~LUA
        local staged = KEYS[1]
        for i = 1, #ARGV, 2 do
          if redis.call('HINCRBY', staged, ARGV[i], -tonumber(ARGV[i + 1])) <= 0 then
            redis.call('HDEL', staged, ARGV[i])
          end
        end
      LUA

      def add(attributes)
        raise ArgumentError, 'expects a single bucket hash' if attributes.is_a?(Array)

        Gitlab::Redis::SharedState.with do |redis|
          redis.hincrby(buffer_key, field_for(attributes), 1)
        end
      end

      def pop(_limit)
        raise NotImplementedError, 'counts are hash-shaped; stage! then staged_batch'
      end

      def stage!
        Gitlab::Redis::SharedState.with do |redis|
          redis.eval(LUA_STAGE_SCRIPT, keys: [buffer_key, staged_key])
        end
      end

      # Non-atomic read is safe: only the flush worker reads this hash, under a lease.
      def staged_batch(limit)
        Gitlab::Redis::SharedState.with do |redis|
          fields = redis.hkeys(staged_key).first(limit)

          next [] if fields.empty?

          counts = redis.hmget(staged_key, *fields)

          fields.zip(counts).filter_map { |field, count| row_for(field, count) }
        end
      end

      def staged_size
        Gitlab::Redis::SharedState.with { |redis| redis.hlen(staged_key) }
      end

      def live_size
        Gitlab::Redis::SharedState.with { |redis| redis.hlen(buffer_key) }
      end

      # Subtracts what was written rather than deleting the field, so a concurrent stage! is kept.
      def remove_staged(rows)
        return if rows.empty?

        argv = rows.flat_map { |row| [field_for(row), row[:count]] }

        Gitlab::Redis::SharedState.with do |redis|
          redis.eval(LUA_REMOVE_STAGED_SCRIPT, keys: [staged_key], argv: argv)
        end
      end

      private

      # Hash tag co-locates this with staged_key; RedisClusterValidator does not check EVAL.
      def buffer_key
        "{#{super}}"
      end

      def staged_key
        "#{buffer_key}:staged"
      end

      def field_for(attributes)
        [
          attributes.fetch(:dependency_firewall_policy_rule_id),
          attributes[:project_id],
          attributes[:stat_time].utc.to_i,
          attributes[:outcome]
        ].join(SEPARATOR)
      end

      def row_for(field, count)
        count = count.to_i

        return if count <= 0

        rule_id, project_id, stat_time, outcome = field.split(SEPARATOR)

        {
          dependency_firewall_policy_rule_id: rule_id.presence&.to_i,
          project_id: project_id.to_i,
          stat_time: Time.zone.at(stat_time.to_i).utc,
          outcome: outcome.to_i,
          count: count
        }
      end
    end
  end
end
