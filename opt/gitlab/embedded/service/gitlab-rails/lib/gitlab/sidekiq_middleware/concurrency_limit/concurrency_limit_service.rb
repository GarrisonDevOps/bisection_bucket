# frozen_string_literal: true

module Gitlab
  module SidekiqMiddleware
    module ConcurrencyLimit
      class ConcurrencyLimitService
        REDIS_KEY_PREFIX = 'sidekiq:concurrency_limit'

        delegate :add_to_queue!, :drop_jobs!, :queue_size, :estimated_queue_size, :metadata_key, :has_jobs_in_queue?,
          :resume_processing!, :scope_queued?, :head_job_buffered_at, to: :@queue_manager

        delegate :track_execution_start, :track_execution_end, :cleanup_stale_trackers,
          :concurrent_worker_count, :track_pending_resumed_jobs, :untrack_pending_resumed_job,
          :pending_resumed_jobs_count, :concurrent_counts_by_scope, :track_scoped_execution_start,
          :reserve_resumed_jobs, :release_reserved_jobs, to: :@worker_execution_tracker

        delegate :current_limit, :enqueue_limit, :set_current_limit!, :adaptive_limit, :stored_adaptive_limit,
          :override_active?,
          :set_override_limit!, :clear_override_limit!, :override_status, to: :@limit_manager

        def initialize(worker_name)
          @worker_name = worker_name
          @queue_manager = QueueManager.new(worker_name: worker_name, prefix: REDIS_KEY_PREFIX)
          @worker_execution_tracker = WorkerExecutionTracker.new(worker_name: worker_name, prefix: REDIS_KEY_PREFIX)
          @limit_manager = LimitManager.new(worker_name: worker_name, prefix: REDIS_KEY_PREFIX)
        end

        class << self
          def add_to_queue!(job, context)
            new(job['class']).add_to_queue!(job, context)
          end

          # Removes deferred jobs matching the metadata across the given workers' queues.
          #
          # @param worker_names [Array<String>] worker class names whose deferred queues to purge
          # @param context_metadata [Hash] application-context metadata to match
          # @param timeout [Numeric] seconds budget shared across all the workers' queues
          # @return [Hash] :completed flag (false if any queue timed out) and :deleted_jobs count
          # @see QueueManager#drop_jobs!
          def drop_matching_jobs!(worker_names, context_metadata, timeout: 30)
            return { completed: true, deleted_jobs: 0 } if worker_names.empty? || context_metadata.empty?

            start_time = Gitlab::Metrics::System.monotonic_time
            completed = true
            deleted = 0

            worker_names.each do |worker_name|
              remaining = timeout - (Gitlab::Metrics::System.monotonic_time - start_time)
              if remaining <= 0
                completed = false
                break
              end

              result = new(worker_name).drop_jobs!(context_metadata, timeout: remaining)
              deleted += result[:deleted_jobs]
              completed &&= result[:completed]
            end

            { completed: completed, deleted_jobs: deleted }
          end

          def has_jobs_in_queue?(worker_name)
            new(worker_name).has_jobs_in_queue?
          end

          def resume_processing!(worker_name)
            new(worker_name).resume_processing!
          end

          def queue_size(worker_name)
            new(worker_name).queue_size
          end

          def estimated_queue_size(worker_name)
            new(worker_name).estimated_queue_size
          end

          def metadata_key(worker_name)
            new(worker_name).metadata_key
          end

          def cleanup_stale_trackers(worker_name)
            new(worker_name).cleanup_stale_trackers
          end

          def track_execution_start(worker_name, scope_key = nil, reserved_jid: nil)
            new(worker_name).track_execution_start(scope_key, reserved_jid: reserved_jid)
          end

          def track_execution_end(worker_name, scope_key = nil)
            new(worker_name).track_execution_end(scope_key)
          end

          def concurrent_worker_count(worker_name)
            new(worker_name).concurrent_worker_count
          end

          def track_pending_resumed_jobs(worker_name, count)
            new(worker_name).track_pending_resumed_jobs(count)
          end

          def untrack_pending_resumed_job(worker_name, count = 1)
            new(worker_name).untrack_pending_resumed_job(count)
          end

          def pending_resumed_jobs_count(worker_name)
            new(worker_name).pending_resumed_jobs_count
          end

          def concurrent_counts_by_scope(worker_name)
            new(worker_name).concurrent_counts_by_scope
          end

          def release_reserved_jobs(worker_name, jids)
            new(worker_name).release_reserved_jobs(jids)
          end

          def scope_queued?(worker_name, scope_key)
            new(worker_name).scope_queued?(scope_key)
          end

          def current_limit(worker_name)
            new(worker_name).current_limit
          end

          def enqueue_limit(worker_name)
            new(worker_name).enqueue_limit
          end

          def set_current_limit!(worker_name, limit:)
            new(worker_name).set_current_limit!(limit)
          end

          def adaptive_limit(worker_name)
            new(worker_name).adaptive_limit
          end

          def override_active?(worker_name)
            new(worker_name).override_active?
          end

          def set_override_limit!(worker_name, limit:, ttl: LimitManager::TTL.to_i)
            new(worker_name).set_override_limit!(limit, ttl: ttl)
          end

          def clear_override_limit!(worker_name)
            new(worker_name).clear_override_limit!
          end

          def override_status(worker_name)
            new(worker_name).override_status
          end

          def over_the_limit?(worker_name, limit: nil)
            service = new(worker_name)
            limit ||= service.current_limit

            return false if limit == 0

            service.concurrent_worker_count >= limit
          end

          # Admits a job of a scoped worker, tracking it, unless the worker is at its limit or the scope
          # at its share of it. Returns :limit or :scope when the job must wait, nil when it can run.
          def track_scoped_execution_start(worker_name, scope, scope_key, reserved_jid: nil)
            service = new(worker_name)
            limit = service.current_limit
            if limit == 0
              service.track_execution_start(scope_key, reserved_jid: reserved_jid)
              return
            end

            service.track_scoped_execution_start(limit: limit, scope_key: scope_key,
              scope_limit: scope.limit_for(limit), reserved_jid: reserved_jid)
          end

          # Reserves slots for resumed jobs of a scoped or free-slot worker; returns how many leading jids can
          # be resumed. Resumed jobs reserve against the full limit, not the free-slot admission limit. With
          # the scope off, a job from a scope queue reserves unscoped, so the queue still drains.
          def reserve_resumed_jobs(worker_name, jids, scope, scope_key)
            service = new(worker_name)
            limit = service.current_limit

            service.reserve_resumed_jobs(jids, limit: limit, scope_key: scope ? scope_key : nil,
              scope_limit: scope ? scope.limit_for(limit) : 0)
          end

          # Whether a new job of a free-slot worker must wait at enqueue: only when the worker is at its
          # admission limit, however many jobs are deferred.
          def free_slot_over_the_limit?(worker_name, limit: nil)
            service = new(worker_name)
            limit ||= service.current_limit
            return false if limit == 0

            service.concurrent_worker_count >= service.free_slot_admission_limit(limit)
          end

          # Admits a job of a free-slot worker, tracking it, unless the worker is at its admission limit.
          # Returns :limit when the job must wait, nil when it can run.
          def track_free_slot_execution_start(worker_name, reserved_jid: nil)
            service = new(worker_name)
            limit = service.current_limit
            return if limit == 0

            service.track_scoped_execution_start(limit: service.free_slot_admission_limit(limit),
              scope_key: nil, scope_limit: 0, reserved_jid: reserved_jid)
          end
        end

        # The limit new jobs of a free-slot worker are admitted against, see FreeSlots.admission_limit.
        def free_slot_admission_limit(limit)
          FreeSlots.admission_limit(limit, head_job_buffered_at)
        end
      end
    end
  end
end
