# frozen_string_literal: true

module Gitlab
  module SidekiqMiddleware
    module ConcurrencyLimit
      class QueueManager
        include ExclusiveLeaseGuard
        include Gitlab::ExclusiveLeaseHelpers

        MAX_PROCESSING_TIME = 5.minutes
        LEASE_TIMEOUT = MAX_PROCESSING_TIME + 2.seconds
        MAX_BATCH_SIZE = 5_000
        # Bounded wait for the shared lease before drop_jobs! gives up (admin can retry).
        DROP_LOCK_RETRIES = 10
        DROP_LOCK_SLEEP = 0.5.seconds
        # Bounds the scopes read from the scopes set per draw, and the draws per resume pass.
        MAX_SCOPE_SAMPLE = 1_000
        MAX_SCOPE_DRAWS = 3
        NON_TRANSIENT_ERRORS = [
          Gitlab::SidekiqMiddleware::SizeLimiter::ExceedLimitError,
          JSON::ParserError
        ].freeze

        # Replayed onto the resumed job: the size-limiter compression markers, so the server-side
        # middleware decompresses its still-compressed `args`, and the concurrency limit scope key.
        PRESERVED_JOB_KEYS = [
          ::Gitlab::SidekiqMiddleware::SizeLimiter::Compressor::COMPRESSED_KEY,
          ::Gitlab::SidekiqMiddleware::SizeLimiter::Compressor::ORIGINAL_SIZE_KEY,
          Scope::JOB_KEY
        ].freeze

        # KEYS: scope queue, scopes set. ARGV: scope key.
        # Atomic so a job added between the length check and the removal keeps its scope listed.
        FORGET_EMPTY_SCOPE_SCRIPT = ::Labkit::Redis::Script.new(<<~LUA)
          if redis.call('llen', KEYS[1]) == 0 then
            redis.call('srem', KEYS[2], ARGV[1])
          end
        LUA

        attr_reader :redis_key, :metadata_key, :worker_name

        def initialize(worker_name:, prefix:)
          @worker_name = worker_name
          @redis_key = "#{prefix}:throttled_jobs:{#{worker_name.underscore}}"
          @metadata_key = "#{prefix}:resume_meta:{#{worker_name.underscore}}"
          @drop_request_key = "#{prefix}:drop_requested:{#{worker_name.underscore}}"
          # Jobs with a scope key wait in a queue per scope, so one scope's backlog does not hold
          # back the others' deferred jobs. The set lists the scopes with a non-empty queue.
          @scopes_key = "#{prefix}:throttled_scopes:{#{worker_name.underscore}}"
        end

        def add_to_queue!(job, context)
          scope_key = job[Scope::JOB_KEY]

          with_redis do |redis|
            if scope_key
              redis.multi do |transaction|
                transaction.rpush(scope_queue_key(scope_key), serialize(job, context))
                transaction.sadd(@scopes_key, scope_key)
              end
            else
              redis.rpush(@redis_key, serialize(job, context))
            end
          end

          deferred_job_counter.increment({ worker: @worker_name })
        end

        # Removes deferred jobs from this worker's queue whose context matches the metadata.
        #
        # @param context_metadata [Hash] application-context metadata to match against each job
        # @param timeout [Numeric] seconds budget before stopping early
        # @return [Hash] :completed flag and :deleted_jobs count
        # @see #resume_processing!
        def drop_jobs!(context_metadata, timeout:)
          # Skip the drop-request/lock handshake when there is nothing to remove: callers may
          # iterate over every worker routed to a queue, and most deferred queues are empty.
          return { completed: true, deleted_jobs: 0 } unless has_jobs_in_queue?

          start_time = monotonic_time
          timed_out = false
          deleted = 0

          # Signal intent so resume_processing! yields the shared lease, then acquire the same
          # lease before mutating: resume trims from the head by position (ltrim) while we remove
          # by value (lrem), which could otherwise drop an unprocessed job. The flag TTL matches
          # the operation budget so it covers the whole run and self-heals if this process dies.
          request_drop!(timeout)

          in_lock(lease_key, ttl: LEASE_TIMEOUT, retries: DROP_LOCK_RETRIES, sleep_sec: DROP_LOCK_SLEEP) do
            with_redis do |redis|
              each_queue(redis) do |queue_key, scope_key|
                break if timed_out

                # We hold the lease, so we are the only remover: track deletions locally instead of
                # inferring from llen, which concurrent add_to_queue! rpushes would inflate (causing
                # range_start to overshoot and skip unexamined entries).
                deleted_before = deleted
                deleted_size = 0
                page = 0

                loop do
                  range_start = (page * MAX_BATCH_SIZE) - deleted_size
                  entries = redis.lrange(queue_key, range_start, range_start + MAX_BATCH_SIZE - 1)
                  break if entries.empty?

                  page += 1
                  entries.each do |job_json|
                    if timeout_exceeded?(start_time, timeout)
                      timed_out = true
                      break
                    end

                    job = deserialize(job_json)
                    next unless job_matches?(job, context_metadata)

                    deleted += redis.lrem(queue_key, 1, job_json)
                  rescue ::JSON::ParserError
                    next
                  end

                  break if timed_out

                  deleted_size = deleted - deleted_before
                end

                forget_scope_if_empty(redis, scope_key) if scope_key
              end
            end
          end

          { completed: !timed_out, deleted_jobs: deleted }
        rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
          # Resume is actively processing this queue; the caller can retry.
          { completed: false, deleted_jobs: deleted }
        ensure
          clear_drop_request!
        end

        # Exact enough for metrics (SSCAN may count a scope twice while the set rehashes).
        # Costs about two round trips per MAX_SCOPE_SAMPLE queued scopes.
        def queue_size
          with_redis do |redis|
            enum_for(:each_queue, redis).each_slice(MAX_SCOPE_SAMPLE).sum do |queues|
              redis.pipelined { |pipeline| queues.each { |(queue_key)| pipeline.llen(queue_key) } }.sum
            end
          end
        end

        # Exact while the scopes set fits in one sample. Beyond that, the scope queues are
        # extrapolated from a random sample, so it is cheap but high-variance: log-only.
        def estimated_queue_size
          with_redis do |redis|
            main_size, scope_count, sample = redis.pipelined do |pipeline|
              pipeline.llen(@redis_key)
              pipeline.scard(@scopes_key)
              pipeline.srandmember(@scopes_key, MAX_SCOPE_SAMPLE)
            end

            sampled = redis.pipelined { |pipeline| sample.each { |key| pipeline.llen(scope_queue_key(key)) } }.sum
            sampled = (sampled * scope_count.fdiv(sample.size)).round if sample.size == MAX_SCOPE_SAMPLE

            main_size + sampled
          end
        end

        def scope_queued?(scope_key)
          with_redis { |redis| redis.sismember(@scopes_key, scope_key) }
        end

        # @return [Float, nil] when the oldest job in the main queue was deferred, nil when it is empty
        def head_job_buffered_at
          job_json = with_redis { |redis| redis.lindex(@redis_key, 0) }
          return unless job_json

          deserialize(job_json)['buffered_at']
        rescue JSON::ParserError
          nil
        end

        def has_jobs_in_queue?
          with_redis do |redis|
            redis.pipelined do |pipeline|
              pipeline.llen(@redis_key)
              pipeline.scard(@scopes_key)
            end.any?(&:positive?)
          end
        end

        def resume_processing!
          # Yield to a pending drop_jobs! request so an admin purge is not starved while we hold
          # the lease across a long resume run.
          return 0 if drop_requested?

          try_obtain_lease do
            with_redis do |redis|
              unless Feature.enabled?(:concurrency_limit_eager_resume_processing, :instance, type: :ops)
                resumed_jobs_count = resume_processing_once!(redis)
                break resumed_jobs_count
              end

              deadline = MAX_PROCESSING_TIME.from_now
              total_resumed_jobs = 0
              while deadline.future?
                break unless renew_lease!
                break if drop_requested?

                resumed_jobs_count = resume_processing_once!(redis)
                break if resumed_jobs_count == 0

                total_resumed_jobs += resumed_jobs_count
              end
              total_resumed_jobs
            end
          end
        end

        private

        def lease_timeout
          LEASE_TIMEOUT
        end

        def lease_key
          @lease_key ||= "concurrency_limit:queue_manager:{#{worker_name.underscore}}"
        end

        def lease_taken_log_level
          :info
        end

        # Signals that an admin {#drop_jobs!} wants this worker's queue, so {#resume_processing!} yields.
        #
        # @param ttl [Numeric] seconds the flag lives; matches the drop budget so it covers the run
        # @see #resume_processing!
        def request_drop!(ttl)
          with_redis { |redis| redis.set(@drop_request_key, true, ex: [ttl.ceil, 1].max) }
        end

        # Whether an admin {#drop_jobs!} is waiting for this worker's queue.
        #
        # @return [Boolean]
        # @see #drop_jobs!
        def drop_requested?
          with_redis { |redis| redis.exists?(@drop_request_key) } # rubocop:disable CodeReuse/ActiveRecord -- Redis, not ActiveRecord
        end

        # Clears the drop-requested flag once the admin {#drop_jobs!} has finished.
        #
        # @see #drop_jobs!
        def clear_drop_request!
          with_redis { |redis| redis.del(@drop_request_key) }
        end

        def resume_processing_once!(redis)
          scope = reserving_scope
          reserving = reserving?(scope)
          limit = reserving ? worker_limit - concurrent_worker_count : num_jobs_to_resume
          return 0 unless limit > 0

          # Skips scopes at their share without reading their queues; the reservation is what binds.
          scope_limit = scope&.limit_for(worker_limit)
          used = scope ? ConcurrencyLimitService.concurrent_counts_by_scope(worker_name) : {}

          # A pass serves at most `limit` scopes, so it draws a bounded random sample of them
          # instead of reading the whole set, and draws again while slots remain.
          total_resumed = 0
          seen = []
          candidates = [[@redis_key, nil]]

          MAX_SCOPE_DRAWS.times do
            count = [limit * 2, MAX_SCOPE_SAMPLE].min
            drawn = redis.srandmember(@scopes_key, count)
            candidates += (drawn - seen).map { |scope_key| [scope_queue_key(scope_key), scope_key] }
            seen.concat(drawn)

            # Random order, so no queue is always served first when the limit runs out.
            candidates.shuffle.each do |queue_key, scope_key|
              room = scope && scope_key ? [limit, scope_limit - used.fetch(scope_key, 0)].min : limit
              next unless room > 0

              resumed = resume_from_queue!(redis, queue_key, room, scope, scope_key, reserving: reserving)
              forget_scope_if_empty(redis, scope_key) if scope_key
              limit -= resumed
              total_resumed += resumed
            end

            # SRANDMEMBER returns the whole set when it holds fewer members than requested.
            break if drawn.size < count || limit <= 0

            candidates = []
          end

          total_resumed
        end

        # Scoped workers reserve the slot of each job they resume, see WorkerExecutionTracker#reserve_resumed_jobs.
        def reserving_scope
          scope = Scope.for(worker_klass)
          scope if scope && worker_limit > 0
        end

        # Scoped workers reserve the slot of each resumed job. Free-slot workers reserve too: new jobs admitted
        # beside the deferred ones would otherwise take the slots counted free for this batch before the
        # resumed jobs start.
        def reserving?(scope)
          scope.present? || (worker_limit > 0 && FreeSlots.enabled_for?(worker_klass))
        end

        def resume_from_queue!(redis, queue_key, limit, scope, scope_key, reserving:)
          jobs = next_batch_from_queue(redis, queue_key, limit: limit)
          jobs = jobs.first(reserve(jobs, scope, scope_key)) if reserving
          return 0 if jobs.empty?

          begin
            bulk_send_to_processing_queue(jobs, reserved: reserving)
          rescue StandardError => e
            if non_transient_error?(e)
              send_jobs_individually(jobs, queue_key, reserved: reserving)
              return jobs.length
            end

            release_reservations(jobs) if reserving
            raise
          end

          remove_processed_jobs(redis, queue_key, limit: jobs.length)

          jobs.length
        end

        def reserve(jobs, scope, scope_key)
          ConcurrencyLimitService.reserve_resumed_jobs(worker_name, jobs.map { |job| jid_of(job) }, scope, scope_key)
        end

        def release_reservations(jobs)
          ConcurrencyLimitService.release_reserved_jobs(worker_name, jobs.filter_map { |job| jid_of(job) })
        end

        def jid_of(job_json)
          deserialize(job_json)['jid']
        rescue JSON::ParserError
          nil
        end

        def non_transient_error?(error)
          NON_TRANSIENT_ERRORS.any? { |klass| error.is_a?(klass) }
        end

        def send_jobs_individually(jobs, queue_key, reserved:)
          return 0 if worker_klass.nil?

          enqueued = 0
          jobs.each_with_index do |job, index|
            bulk_send_to_processing_queue([job], reserved: reserved)
            enqueued += 1
          rescue StandardError => e
            unless non_transient_error?(e)
              # Trim the jobs already sent or dropped so a retry does not resend them. The failed
              # job and the rest stay queued, so free the slots reserved for them.
              with_redis { |redis| remove_processed_jobs(redis, queue_key, limit: index) }
              release_reservations(jobs.drop(index)) if reserved
              raise
            end

            release_reservations([job]) if reserved
            log_dropped_job(job, e)
            dropped_job_counter.increment({ worker: @worker_name })
          end

          with_redis do |redis|
            remove_processed_jobs(redis, queue_key, limit: jobs.length)
          end

          enqueued
        end

        def log_dropped_job(job, error)
          Gitlab::SidekiqLogging::ConcurrencyLimitLogger.instance.dropped_poison_job_log(worker_name, job, error)
        end

        def num_jobs_to_resume
          limit = worker_limit
          if limit > 0
            limit - concurrent_worker_count - pending_resumed_jobs_count
          else
            MAX_BATCH_SIZE
          end
        end

        def worker_limit
          Gitlab::SidekiqMiddleware::ConcurrencyLimit::ConcurrencyLimitService.current_limit(worker_name)
        end

        def concurrent_worker_count
          Gitlab::SidekiqMiddleware::ConcurrencyLimit::ConcurrencyLimitService.concurrent_worker_count(worker_name)
        end

        def pending_resumed_jobs_count
          Gitlab::SidekiqMiddleware::ConcurrencyLimit::ConcurrencyLimitService.pending_resumed_jobs_count(worker_name)
        end

        def track_pending_resumed_jobs(count)
          Gitlab::SidekiqMiddleware::ConcurrencyLimit::ConcurrencyLimitService.track_pending_resumed_jobs(worker_name,
            count)
        end

        def untrack_pending_resumed_job(count)
          Gitlab::SidekiqMiddleware::ConcurrencyLimit::ConcurrencyLimitService.untrack_pending_resumed_job(worker_name,
            count)
        end

        def with_redis(&)
          Gitlab::Redis::ConcurrencyLimit.with(&) # rubocop:disable CodeReuse/ActiveRecord -- Not active record
        end

        def serialize(job, context)
          {
            args: job['args'],
            jid: job['jid'],
            context: context,
            buffered_at: Time.now.utc.to_f,
            wal_locations: job['wal_locations']
          }.merge(job.slice(*PRESERVED_JOB_KEYS)).to_json
        end

        def deserialize(json)
          Gitlab::Json.parse(json)
        end

        # @param reserved [Boolean] whether the caller reserved the jobs' slots, instead of the pending counter
        def bulk_send_to_processing_queue(jobs, reserved: false)
          return if worker_klass.nil?

          args_list = prepare_and_store_metadata(jobs, reserved)
          Gitlab::SidekiqLogging::ConcurrencyLimitLogger.instance.batch_resumed_log(worker_name, args_list.length)
          return worker_klass.bulk_perform_async(args_list) if reserved # rubocop:disable Scalability/BulkPerformWithContext -- context is set separately in SidekiqMiddleware::ConcurrencyLimit::Resume

          # Track before enqueuing so the counter is set before any resumed job can be picked
          # up and reach track_execution_start (which calls untrack_pending_resumed_job). A job
          # dequeued in the window before this increment would decrement a counter still floored
          # at zero, losing the decrement and leaving the counter permanently inflated.
          track_pending_resumed_jobs(args_list.length)
          begin
            worker_klass.bulk_perform_async(args_list) # rubocop:disable Scalability/BulkPerformWithContext -- context is set separately in SidekiqMiddleware::ConcurrencyLimit::Resume
          rescue StandardError
            # The batch was not enqueued, so release the slots we just reserved. The caller
            # either retries the jobs individually (re-tracking one per job) or leaves them
            # buffered; either way these jobs will never reach track_execution_start.
            untrack_pending_resumed_job(args_list.length)
            raise
          end
        end

        def prepare_and_store_metadata(jobs, reserved)
          queue = Queue.new
          args_list = []
          klass = worker_klass
          jobs.each do |job|
            deserialized = deserialize(job)
            WorkerHooks.resumed(klass, deserialized)
            queue.push(job_metadata(deserialized, reserved))
            args_list << deserialized['args']
          end

          # Since bulk_perform_async doesn't support updating job payload one by one,
          # we'll rely on Gitlab::SidekiqMiddleware::ConcurrencyLimit::Resume client middleware
          # to update each job with the required metadata.
          Gitlab::SafeRequestStore.write(metadata_key, queue)
          args_list
        end

        def job_metadata(job, reserved)
          {
            'jid' => job['jid'],
            'concurrency_limit_buffered_at' => job['buffered_at'],
            'concurrency_limit_resume' => true,
            'wal_locations' => job['wal_locations']
          }.merge(job['context']).merge(job.slice(*PRESERVED_JOB_KEYS))
            .merge(reserved ? { Scope::RESERVED_JOB_KEY => true } : {})
        end

        def worker_klass
          worker_name.safe_constantize
        end

        def next_batch_from_queue(redis, queue_key, limit:)
          return [] unless limit > 0

          redis.lrange(queue_key, 0, limit - 1)
        end

        def remove_processed_jobs(redis, queue_key, limit:)
          redis.ltrim(queue_key, limit, -1)
        end

        def scope_queue_key(scope_key)
          "#{@redis_key}:scope:#{scope_key}"
        end

        # Yields each queue key with its scope key (nil for the main queue), scanning the scopes set
        # in batches. SSCAN can yield a scope twice; visiting its queue again is harmless.
        def each_queue(redis)
          yield @redis_key, nil
          redis.sscan_each(@scopes_key, count: MAX_SCOPE_SAMPLE) { |key| yield scope_queue_key(key), key }
        end

        def forget_scope_if_empty(redis, scope_key)
          FORGET_EMPTY_SCOPE_SCRIPT.eval(redis, keys: [scope_queue_key(scope_key), @scopes_key], argv: [scope_key])
        end

        def deferred_job_counter
          @deferred_job_counter ||= ::Gitlab::Metrics.counter(:sidekiq_concurrency_limit_deferred_jobs_total,
            'Count of jobs deferred by the concurrency limit middleware.')
        end

        def dropped_job_counter
          @dropped_job_counter ||= ::Gitlab::Metrics.counter(:sidekiq_concurrency_limit_dropped_jobs_total,
            'Count of poison jobs dropped from the concurrency limit buffered queue.')
        end

        # Whether a deferred job's stored context matches all given metadata.
        #
        # @param job [Hash] deserialized deferred job payload
        # @param context_metadata [Hash] metadata to match against the job's context
        # @return [Boolean]
        def job_matches?(job, context_metadata)
          return false if context_metadata.empty?

          context = job['context'] || {}
          context_metadata.all? do |key, value|
            # Deferred jobs do not store their class: the queue itself is per-worker.
            key == 'class' ? value == @worker_name : context[key] == value
          end
        end

        # Whether the elapsed time since start_time exceeds the timeout.
        #
        # @param start_time [Float] monotonic timestamp captured at the start
        # @param timeout [Numeric] seconds budget
        # @return [Boolean]
        def timeout_exceeded?(start_time, timeout)
          (monotonic_time - start_time) > timeout
        end

        # Current monotonic clock reading.
        #
        # @return [Float] monotonic time in seconds
        def monotonic_time
          Gitlab::Metrics::System.monotonic_time
        end
      end
    end
  end
end
