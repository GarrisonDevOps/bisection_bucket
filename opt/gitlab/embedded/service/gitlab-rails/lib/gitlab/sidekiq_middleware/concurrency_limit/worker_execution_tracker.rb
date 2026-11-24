# frozen_string_literal: true

module Gitlab
  module SidekiqMiddleware
    module ConcurrencyLimit
      class WorkerExecutionTracker
        include ExclusiveLeaseGuard

        TRACKING_KEY_TTL = 600.seconds
        SCOPE_SEPARATOR = '|'
        # Executing-hash field prefix for a resumed job's reserved slot, replaced when the job starts.
        RESERVATION_PREFIX = 'resumed:'

        # Lua: changes the executing hash (KEYS[1]) only through track and untrack, which keep the count of
        # executing and reserved jobs per scope key (KEYS[2]) in step, so admission reads one count, not the hash.
        TRACKER_LUA = <<~LUA.freeze
          local function count(value, by)
            local sep = value and string.find(value, '#{SCOPE_SEPARATOR}', 1, true)
            if not sep then
              return
            end
            local scope = string.sub(value, sep + 1)
            if redis.call('hincrby', KEYS[2], scope, by) <= 0 then
              redis.call('hdel', KEYS[2], scope)
            end
          end

          local function track(field, value)
            count(redis.call('hget', KEYS[1], field), -1)
            redis.call('hset', KEYS[1], field, value)
            count(value, 1)
          end

          local function untrack(field)
            local value = redis.call('hget', KEYS[1], field)
            if value then
              redis.call('hdel', KEYS[1], field)
              count(value, -1)
            end
          end

          local function scope_count(scope)
            return tonumber(redis.call('hget', KEYS[2], scope) or 0)
          end
        LUA

        # Admits a job, tracking it, if it holds a reservation of its scope or the worker and its scope both
        # have room. A reservation of another scope (e.g. made while the scope was off) is released first.
        # KEYS: executing hash, scope counts. ARGV: field ('' outside Sidekiq), value, limit, scope key,
        # scope limit, reservation field (''). Returns 1 when the worker is at its limit, 2 when the scope is,
        # 0 once tracked.
        TRACK_SCOPED_EXECUTION_START_SCRIPT = ::Labkit::Redis::Script.new(<<~LUA)
          #{TRACKER_LUA}
          if ARGV[6] ~= '' then
            local reserved = redis.call('hget', KEYS[1], ARGV[6])
            if reserved then
              untrack(ARGV[6])
              local suffix = '#{SCOPE_SEPARATOR}' .. ARGV[4]
              if ARGV[4] == '' or string.sub(reserved, -#suffix) == suffix then
                if ARGV[1] ~= '' then
                  track(ARGV[1], ARGV[2])
                end
                return 0
              end
            end
          end

          if redis.call('hlen', KEYS[1]) >= tonumber(ARGV[3]) then
            return 1
          end

          if ARGV[4] ~= '' and scope_count(ARGV[4]) >= tonumber(ARGV[5]) then
            return 2
          end

          if ARGV[1] ~= '' then
            track(ARGV[1], ARGV[2])
          end
          return 0
        LUA

        # Reserves slots for resumed jobs, in order, while the worker and the scope have room.
        # KEYS: executing hash, scope counts. ARGV: value, limit, scope key ('' if none), scope limit, then
        # the jids ('' for a job without one, which takes no slot). Returns how many leading jobs can be resumed.
        RESERVE_RESUMED_JOBS_SCRIPT = ::Labkit::Redis::Script.new(<<~LUA)
          #{TRACKER_LUA}
          local room = tonumber(ARGV[2]) - redis.call('hlen', KEYS[1])
          if ARGV[3] ~= '' then
            room = math.min(room, tonumber(ARGV[4]) - scope_count(ARGV[3]))
          end

          local accepted = 0
          for i = 5, #ARGV do
            local field = '#{RESERVATION_PREFIX}' .. ARGV[i]
            -- A job resumed again (e.g. after a crash before the queue was trimmed) keeps its slot.
            if ARGV[i] ~= '' and redis.call('hexists', KEYS[1], field) == 0 then
              if room <= 0 then
                break
              end
              track(field, ARGV[1])
              room = room - 1
            end
            accepted = accepted + 1
          end
          return accepted
        LUA

        # KEYS: executing hash, scope counts. ARGV: field, value, the field of the reservation it replaces ('').
        TRACK_EXECUTION_START_SCRIPT = ::Labkit::Redis::Script.new(<<~LUA)
          #{TRACKER_LUA}
          if ARGV[3] ~= '' then
            untrack(ARGV[3])
          end
          track(ARGV[1], ARGV[2])
        LUA

        # KEYS: executing hash, scope counts. ARGV: the fields to remove.
        UNTRACK_SCRIPT = ::Labkit::Redis::Script.new(<<~LUA)
          #{TRACKER_LUA}
          for _, field in ipairs(ARGV) do
            untrack(field)
          end
        LUA

        # Removes the stale fields in ARGV, then recounts the scopes, healing any drift of the counts (e.g. from
        # a deploy that mixes versions). KEYS: executing hash, scope counts.
        CLEANUP_SCRIPT = ::Labkit::Redis::Script.new(<<~LUA)
          for _, field in ipairs(ARGV) do
            redis.call('hdel', KEYS[1], field)
          end

          local counts = {}
          for _, value in ipairs(redis.call('hvals', KEYS[1])) do
            local sep = string.find(value, '#{SCOPE_SEPARATOR}', 1, true)
            if sep then
              local scope = string.sub(value, sep + 1)
              counts[scope] = (counts[scope] or 0) + 1
            end
          end

          redis.call('del', KEYS[2])
          for scope, n in pairs(counts) do
            redis.call('hset', KEYS[2], scope, n)
          end
        LUA

        UNTRACK_PENDING_RESUMED_JOB_SCRIPT = ::Labkit::Redis::Script.new(<<~LUA)
          local count = redis.call('decrby', KEYS[1], ARGV[2])
          if count < 0 then
            redis.call('set', KEYS[1], 0, 'EX', ARGV[1])
            return 0
          end
          return count
        LUA

        def initialize(worker_name:, prefix:)
          @worker_name = worker_name
          @prefix = prefix
        end

        # The scope key is stored beside the start time, so per-scope counts share the stale-tracker
        # cleanup; reserved_jid is a resumed job whose reserved slot this execution takes over.
        def track_execution_start(scope_key = nil, reserved_jid: nil)
          return release_reserved_jobs([reserved_jid].compact) if sidekiq_pid.nil?

          process_thread_id = process_thread_id_key(sidekiq_pid, sidekiq_tid)
          unscoped = scope_key.nil? && reserved_jid.nil?
          with_redis do |r|
            # Unscoped jobs never touch the scope counts, so they skip the script. A scoped entry they replace
            # (one whose end never ran) stays counted until the cleanup recounts.
            next r.hset(worker_executing_hash_key, process_thread_id, tracker_value(nil)) if unscoped

            reservation = reserved_jid ? reservation_field(reserved_jid) : ''
            TRACK_EXECUTION_START_SCRIPT.eval(r, keys: tracker_keys,
              argv: [process_thread_id, tracker_value(scope_key), reservation])
          end
        end

        # Checks the worker limit and the scope's share and tracks the execution in one step, so jobs picked
        # up together cannot all pass. A resumed job whose reservation was cleaned up, or is of another scope,
        # is checked like a new one.
        # Returns :limit or :scope when the job must wait, nil when it can run.
        def track_scoped_execution_start(limit:, scope_key:, scope_limit:, reserved_jid: nil)
          process_thread_id = sidekiq_pid.nil? ? '' : process_thread_id_key(sidekiq_pid, sidekiq_tid)
          reservation = reserved_jid ? reservation_field(reserved_jid) : ''

          result = with_redis do |r|
            TRACK_SCOPED_EXECUTION_START_SCRIPT.eval(r, keys: tracker_keys,
              argv: [process_thread_id, tracker_value(scope_key), limit, scope_key.to_s, scope_limit, reservation])
          end

          { 1 => :limit, 2 => :scope }[result]
        end

        # Reserving in the executing hash counts resumed jobs against the limit as soon as they are picked;
        # the reservation of a job that never starts goes with the stale-tracker cleanup.
        # @return [Integer] how many of the leading jids (in queue order) can be resumed
        def reserve_resumed_jobs(jids, limit:, scope_key:, scope_limit:)
          with_redis do |r|
            RESERVE_RESUMED_JOBS_SCRIPT.eval(r, keys: tracker_keys,
              argv: [tracker_value(scope_key), limit, scope_key.to_s, scope_limit, *jids.map(&:to_s)])
          end
        end

        def release_reserved_jobs(jids)
          return if jids.empty?

          untrack(jids.map { |jid| reservation_field(jid) })
        end

        # scope_key is the one the execution started with; without one, the entry holds no scope count.
        def track_execution_end(scope_key = nil)
          return if sidekiq_pid.nil?

          process_thread_id = process_thread_id_key(sidekiq_pid, sidekiq_tid)
          return untrack([process_thread_id]) if scope_key

          with_redis { |r| r.hdel(worker_executing_hash_key, process_thread_id) }
        end

        # Runs even when nothing is stale, so the scope counts are recounted once per lease.
        def cleanup_stale_trackers
          try_obtain_lease do
            executing_threads_hash = with_redis { |r| r.hgetall(worker_executing_hash_key) }
            dangling = executing_threads_hash.filter_map { |k, v| k unless still_executing?(k, v) }

            with_redis { |r| CLEANUP_SCRIPT.eval(r, keys: tracker_keys, argv: dangling) }
          end
        end

        def concurrent_worker_count
          with_redis { |r| r.hlen(worker_executing_hash_key).to_i }
        end

        # @return [Hash{String => Integer}] executing and reserved job count per scope key
        def concurrent_counts_by_scope
          with_redis { |r| r.hgetall(scope_counts_key) }.transform_values(&:to_i)
        end

        # Tracks jobs that have been resumed (enqueued for processing) but have not
        # started executing yet, so they can be counted against the concurrency limit
        # when deciding how many further jobs to resume. See QueueManager#num_jobs_to_resume.
        def track_pending_resumed_jobs(count)
          return if count <= 0

          with_redis do |r|
            r.pipelined do |pipeline|
              pipeline.incrby(pending_resumed_jobs_key, count)
              pipeline.expire(pending_resumed_jobs_key, TRACKING_KEY_TTL.to_i)
            end
          end
        end

        def untrack_pending_resumed_job(count = 1)
          return if count <= 0

          # Decrement and floor at zero atomically so a concurrent num_jobs_to_resume never
          # observes a negative intermediate value, which would inflate the resume batch.
          # The floor guards against drift (e.g. the counter expiring before the job starts).
          with_redis do |r|
            UNTRACK_PENDING_RESUMED_JOB_SCRIPT.eval(r,
              keys: [pending_resumed_jobs_key], argv: [TRACKING_KEY_TTL.to_i, count])
          end
        end

        def pending_resumed_jobs_count
          with_redis { |r| r.get(pending_resumed_jobs_key).to_i }
        end

        private

        attr_reader :worker_name

        def lease_timeout
          TRACKING_KEY_TTL
        end

        def lease_key
          "#{@prefix}:{#{worker_name.underscore}}"
        end

        def lease_release?
          false
        end

        def lease_taken_log_level
          :debug
        end

        def with_redis(&)
          Redis::QueuesMetadata.with(&) # rubocop:disable CodeReuse/ActiveRecord -- Not active record
        end

        def worker_executing_hash_key
          "#{@prefix}:{#{worker_name.underscore}}:executing"
        end

        # Shares the executing hash's hash tag, so one script can change both.
        def scope_counts_key
          "#{@prefix}:{#{worker_name.underscore}}:scope_counts"
        end

        def tracker_keys
          [worker_executing_hash_key, scope_counts_key]
        end

        def untrack(fields)
          with_redis { |r| UNTRACK_SCRIPT.eval(r, keys: tracker_keys, argv: fields) }
        end

        def pending_resumed_jobs_key
          "#{@prefix}:{#{worker_name.underscore}}:pending_resumed"
        end

        def reservation_field(jid)
          "#{RESERVATION_PREFIX}#{jid}"
        end

        def tracker_value(scope_key)
          [Time.now.utc.tv_sec, scope_key].compact.join(SCOPE_SEPARATOR)
        end

        def process_thread_id_key(pid, tid)
          "#{pid}:tid:#{tid}"
        end

        def sidekiq_pid
          Gitlab::SidekiqProcess.pid
        end

        def sidekiq_tid
          Gitlab::SidekiqProcess.tid
        end

        def still_executing?(ptid, started_at)
          return true unless started_at.to_i < TRACKING_KEY_TTL.ago.utc.to_i

          pid, tid = ptid.split(":tid:")
          return false unless pid && tid

          job_hash = fetch_sidekiq_process_work_hash(pid, tid)
          return false if job_hash.empty?

          job_hash['class'] == worker_name
        end

        def fetch_sidekiq_process_work_hash(pid, tid)
          job_hash = {}
          Gitlab::SidekiqSharding::Router.route(worker_name.safe_constantize) do
            hash = Sidekiq.redis { |r| r.hget("#{pid}:work", tid) } # rubocop:disable Cop/SidekiqRedisCall -- checking process work hash
            next if hash.nil?

            # There are 2 layers of JSON encoding
            # 1. when a job is pushed into the queue -- https://github.com/sidekiq/sidekiq/blob/v7.3.9/lib/sidekiq/client.rb#L281
            # 2. When the workstate is written into the pid:work hash -- https://github.com/sidekiq/sidekiq/blob/v7.3.9/lib/sidekiq/launcher.rb#L148
            job_hash = ::Gitlab::Json.parse(::Gitlab::Json.parse(hash)&.dig('payload'))
          end

          job_hash
        rescue JSON::ParserError => e
          Gitlab::ErrorTracking.track_exception(e, worker_class: worker_name)
          {}
        end
      end
    end
  end
end
