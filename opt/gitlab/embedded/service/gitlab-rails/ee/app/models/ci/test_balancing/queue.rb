# frozen_string_literal: true

module Ci
  module TestBalancing
    # Redis-backed pending queue for a single parallel job group.
    #
    # The queue is a sorted set keyed by test_split_id with the expected duration as
    # the score. Claims are duration-budgeted and atomic: a Lua script pops the
    # slowest pending tests up to a tapering budget, moves them into a per-node
    # backup set (until PostgreSQL records the claim), and
    # decrements a running-sum key used to compute the budget in O(1).
    class Queue
      MAX_CLAIM_ITEMS = 50
      MIN_CLAIM_BUDGET = 10.0
      MAX_CLAIM_BUDGET = 600.0

      # Duration assigned to a test split with no recorded timing
      DEFAULT_DURATION = 300.0

      TTL = 24.hours.to_i

      # Seed items idempotently and keep the running sum in step:
      #   KEYS[1] queue zset, KEYS[2] running sum key
      #   ARGV[1..] score, member, score, member, ...
      SEED_SCRIPT = ::Labkit::Redis::Script.new(<<~LUA)
        local queue_key, sum_key = KEYS[1], KEYS[2]

        local added_sum = 0.0
        for i = 1, #ARGV, 2 do
          local score = tonumber(ARGV[i])
          local member = ARGV[i + 1]

          local added = redis.call('zadd', queue_key, 'NX', score, member)

          if added == 1 then
            added_sum = added_sum + score
          end
        end

        if added_sum ~= 0 then
          redis.call('incrbyfloat', sum_key, added_sum)
        end

        redis.call('expire', queue_key, #{TTL})
        redis.call('expire', sum_key, #{TTL})

        return tostring(added_sum)
      LUA

      # Atomically claim a budgeted batch:
      #   KEYS[1] queue zset, KEYS[2] node backup zset, KEYS[3] running-sum key,
      #   KEYS[4] node last request hash (run_id, seq), KEYS[5] node last batch zset
      #   ARGV[1] budget, ARGV[2] run ID (empty when not given), ARGV[3] sequence number
      # Returns a flat [score, member, score, member, ...] array of claimed items.
      # Claims at least one item even when it is over the given budget.
      #
      # For the node's last run, a repeated sequence number is a client retry whose
      # response was lost, so the last batch is returned again. A lower one is a
      # late attempt the client already gave up on, so nothing is claimed.
      CLAIM_SCRIPT = ::Labkit::Redis::Script.new(<<~LUA)
        local queue_key, backup_key, sum_key = KEYS[1], KEYS[2], KEYS[3]
        local last_request_key, last_batch_key = KEYS[4], KEYS[5]
        local budget = tonumber(ARGV[1])
        local run_id = ARGV[2]
        local seq = tonumber(ARGV[3])

        if run_id ~= '' then
          local last = redis.call('hmget', last_request_key, 'run_id', 'seq')

          if last[1] == run_id then
            local last_seq = tonumber(last[2])

            if seq < last_seq then
              return {}
            end

            if seq == last_seq then
              local last_batch = redis.call('zrange', last_batch_key, 0, -1, 'REV', 'WITHSCORES')

              local replay = {}
              for j = 1, #last_batch, 2 do
                replay[#replay + 1] = last_batch[j + 1]
                replay[#replay + 1] = last_batch[j]
              end

              return replay
            end
          end
        end

        local candidates = redis.call('ZRANGE', queue_key, 0, #{MAX_CLAIM_ITEMS} - 1, 'REV', 'WITHSCORES')

        local claimed = {}
        local claimed_sum = 0.0
        local backup_args = {}

        local i = 1
        while i <= #candidates do
          local member = candidates[i]
          local score = tonumber(candidates[i + 1])

          if #claimed > 0 and claimed_sum + score > budget then
            break
          end

          claimed[#claimed + 1] = member
          claimed_sum = claimed_sum + score

          backup_args[#backup_args + 1] = candidates[i + 1]
          backup_args[#backup_args + 1] = member

          i = i + 2
        end

        if #claimed > 0 then
          redis.call('zrem', queue_key, unpack(claimed))
          redis.call('zadd', backup_key, unpack(backup_args))
          redis.call('incrbyfloat', sum_key, -claimed_sum)

          redis.call('expire', queue_key, #{TTL})
          redis.call('expire', sum_key, #{TTL})
          redis.call('expire', backup_key, #{TTL})
        else
          redis.call('del', sum_key)
        end

        if run_id ~= '' then
          redis.call('del', last_batch_key)

          if #backup_args > 0 then
            redis.call('zadd', last_batch_key, unpack(backup_args))
            redis.call('expire', last_batch_key, #{TTL})
          end

          redis.call('hset', last_request_key, 'run_id', run_id, 'seq', seq)
          redis.call('expire', last_request_key, #{TTL})
        end

        return backup_args
      LUA

      def initialize(pipeline_id:, job_group_id:, node_index:, node_total:)
        @pipeline_id = pipeline_id
        @job_group_id = job_group_id
        @node_index = node_index
        @node_total = node_total
      end

      # entries: array of { test_split_id:, expected_duration: }
      def seed(entries)
        return 0 if entries.empty?

        argv = []
        entries.each do |entry|
          argv << (entry[:expected_duration] || DEFAULT_DURATION).to_f
          argv << entry[:test_split_id]
        end

        with_redis do |redis|
          SEED_SCRIPT.eval(redis, keys: [queue_key, sum_key], argv: argv).to_f
        end
      end

      # Returns array of { test_split_id:, expected_duration: } claimed for the node.
      #
      # @param run_id [String, nil] ID of the client process, constant across its requests
      # @param seq [Integer, nil] sequence number of the request within the run, reused on retries
      def claim(run_id: nil, seq: nil)
        raw = with_redis do |redis|
          CLAIM_SCRIPT.eval(
            redis,
            keys: [queue_key, backup_key, sum_key, last_request_key, last_batch_key],
            argv: [budget(redis), run_id.to_s, seq.to_i]
          )
        end

        return [] if raw.blank?

        raw.each_slice(2).map do |score, member|
          { test_split_id: member.to_i, expected_duration: score.to_f }
        end
      end

      # Returns the number of pending tests currently in the queue.
      def size
        with_redis do |redis|
          redis.zcard(queue_key)
        end
      end

      # Returns array of { test_split_id:, expected_duration: } currently held in the node backup.
      def backup
        raw = with_redis do |redis|
          redis.zrange(backup_key, 0, -1, rev: true, with_scores: true)
        end

        raw.map { |member, score| { test_split_id: member.to_i, expected_duration: score.to_f } }
      end

      def clear_backup
        with_redis do |redis|
          redis.del(backup_key)
        end
      end

      private

      attr_reader :pipeline_id, :job_group_id, :node_index, :node_total

      # Duration budget for a single claim computed based on remaining duration.
      #
      # When the queue is full, we want to claim larger batches to reduce the number
      # of round trips. When it's near the end, we claim smaller batches to ensure
      # better balancing across nodes.
      def budget(redis)
        pending_sum = redis.get(sum_key).to_f

        (pending_sum / node_total)
          .clamp(MIN_CLAIM_BUDGET, MAX_CLAIM_BUDGET)
      end

      def queue_key
        "test_balancing:#{scope}:queue"
      end

      def sum_key
        "test_balancing:#{scope}:sum"
      end

      def backup_key
        "test_balancing:#{scope}:node:#{node_index}:backup"
      end

      def last_request_key
        "test_balancing:#{scope}:node:#{node_index}:last_request"
      end

      def last_batch_key
        "test_balancing:#{scope}:node:#{node_index}:last_batch"
      end

      # All keys for a job group share the {pipeline_id:job_group_id} hash tag so
      # the multi-key Lua scripts stay on a single Redis Cluster slot.
      def scope
        "{#{pipeline_id}:#{job_group_id}}"
      end

      def with_redis(&block)
        Gitlab::Redis::SharedState.with(&block)
      end
    end
  end
end
