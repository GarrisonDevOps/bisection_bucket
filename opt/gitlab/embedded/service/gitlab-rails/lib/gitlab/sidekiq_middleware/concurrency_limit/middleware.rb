# frozen_string_literal: true

module Gitlab
  module SidekiqMiddleware
    module ConcurrencyLimit
      class Middleware
        include Gitlab::Utils::StrongMemoize

        def initialize(worker, job)
          @worker = worker
          @job = job

          @worker_class = if worker.is_a?(Class)
                            worker
                          elsif worker.is_a?(String)
                            worker.safe_constantize
                          else
                            worker.class
                          end

          @worker_name = worker_class ? worker_class.name : nil
        end

        # This will continue the middleware chain if the job should be scheduled
        # It will return false if the job needs to be cancelled
        def schedule
          if should_defer_schedule?
            defer_job!
            return
          end

          yield
        end

        # This will continue the server middleware chain if the job should be
        # executed.
        # It will return false if the job should not be executed.
        def perform
          if should_defer_perform?
            defer_job!
            return
          end

          track_execution_start

          yield
        ensure
          track_execution_end
          cleanup_stale_trackers
        end

        private

        attr_reader :job, :worker, :worker_name, :worker_class

        def should_defer_schedule?
          return false if disabled_for_worker?
          return false if job['at'] # scheduled jobs can be later assessed on enqueue
          return false if resumed?
          return false if schedule_limit == 0
          return scoped_job_must_wait? if scope
          return free_slot_job_must_wait? if free_slots?

          schedule_backlog?
        end

        def should_defer_perform?
          return false if disabled_for_worker?
          # Resumed jobs of scoped and free-slot workers are checked too, unless they still hold their reservation.
          return !admit_scoped_job if scope
          return !admit_free_slot_job if free_slots?
          return false if resumed?

          return true if has_jobs_in_queue?

          concurrency_service.over_the_limit?(worker_name)
        end

        # A free-slot worker's new jobs wait only while the worker is at its limit, not behind the deferred list.
        def free_slot_job_must_wait?
          return false unless schedule_backlog?

          concurrency_service.free_slot_over_the_limit?(worker_name, limit: (schedule_limit if shared_enqueue_limit?))
        end

        def admit_free_slot_job
          reason = concurrency_service.track_free_slot_execution_start(worker_name, reserved_jid: reserved_jid)
          # A job resumed through the pending counter leaves it when deferred again.
          concurrency_service.untrack_pending_resumed_job(worker_name) if reason && resumed? && !reserved_jid

          reason.nil?
        end

        def free_slots?
          FreeSlots.enabled_for?(worker_class)
        end
        strong_memoize_attr :free_slots?

        # Unlike other workers, a scoped worker's jobs wait behind queued jobs only when those are of the
        # same scope, or the worker is at its limit, so one scope's backlog does not hold back the others.
        def scoped_job_must_wait?
          if scope_key && concurrency_service.scope_queued?(worker_name, scope_key)
            count_scope_deferral
            return true
          end

          return false unless schedule_backlog?

          concurrency_service.over_the_limit?(worker_name, limit: (schedule_limit if shared_enqueue_limit?))
        end

        # Tracks the execution when the job is admitted, so track_execution_start leaves it alone.
        def admit_scoped_job
          reason = concurrency_service.track_scoped_execution_start(worker_name, scope, scope_key,
            reserved_jid: reserved_jid)
          count_scope_deferral if reason == :scope
          # A job resumed through the pending counter leaves it when deferred again.
          concurrency_service.untrack_pending_resumed_job(worker_name) if reason && resumed? && !reserved_jid

          @tracked_on_admission = reason.nil?
        end

        def reserved_jid
          job['jid'] if resumed? && job[Scope::RESERVED_JOB_KEY]
        end

        def count_scope_deferral
          scope_deferred_job_counter.increment({ worker: worker_name, scope: scope.type.to_s })
        end

        def scope
          ::Gitlab::SidekiqMiddleware::ConcurrencyLimit::Scope.for(worker_class)
        end
        strong_memoize_attr :scope

        # Resolved on enqueue and stored on the job, so the server, the deferred payload, logs and
        # a resumed job carry it without resolving it again.
        def scope_key
          return job[Scope::JOB_KEY] if job.key?(Scope::JOB_KEY)
          return unless scope

          key = scope.key_for(job)
          scope_unattributed_job_counter.increment({ worker: worker_name, scope: scope.type.to_s }) unless key
          job[Scope::JOB_KEY] = key
        end
        strong_memoize_attr :scope_key

        def concurrency_service
          ::Gitlab::SidekiqMiddleware::ConcurrencyLimit::ConcurrencyLimitService
        end

        def track_execution_start
          # A resumed job transitions from pending to executing here, so release its slot in
          # the pending counter tracked at enqueue time in QueueManager.
          concurrency_service.untrack_pending_resumed_job(worker_name) if resumed? && !reserved_jid

          if Feature.disabled?(:sidekiq_concurrency_limit_middleware, Feature.current_request, type: :ops)
            concurrency_service.release_reserved_jobs(worker_name, [reserved_jid]) if reserved_jid
            return
          end

          return if @tracked_on_admission

          concurrency_service.track_execution_start(worker_name, scope_key, reserved_jid: reserved_jid)
        end

        def track_execution_end
          return if Feature.disabled?(:sidekiq_concurrency_limit_middleware, Feature.current_request, type: :ops)

          concurrency_service.track_execution_end(worker_name, scope_key)
        end

        def cleanup_stale_trackers
          return if Feature.disabled?(:sidekiq_concurrency_limit_middleware, Feature.current_request, type: :ops)

          concurrency_service.cleanup_stale_trackers(worker_name)
        end

        def worker_limit
          worker_class.respond_to?(:get_concurrency_limit) ? worker_class.get_concurrency_limit : 0
        end

        def schedule_limit
          return worker_limit unless shared_enqueue_limit?
          return 0 if Feature.disabled?(:sidekiq_concurrency_limit_middleware, Feature.current_request, type: :ops)
          return 0 unless schedule_backlog?

          concurrency_service.enqueue_limit(worker_name)
        end
        strong_memoize_attr :schedule_limit

        def shared_enqueue_limit?
          EnqueueLimit.enabled_for?(worker_class)
        end
        strong_memoize_attr :shared_enqueue_limit?

        def schedule_backlog?
          has_jobs_in_queue?
        end
        strong_memoize_attr :schedule_backlog?

        def resumed?
          job['concurrency_limit_resume'] == true
        end

        def has_jobs_in_queue?
          concurrency_service.has_jobs_in_queue?(worker_name)
        end

        def current_count
          ::Gitlab::SidekiqMiddleware::ConcurrencyLimit::ConcurrencyLimitService.concurrent_worker_count(worker_name)
        end

        def scope_deferred_job_counter
          ::Gitlab::Metrics.counter(:sidekiq_concurrency_limit_scope_deferred_jobs_total,
            'Count of jobs deferred because their scope is at its share of the concurrency limit or has queued jobs.')
        end

        def scope_unattributed_job_counter
          ::Gitlab::Metrics.counter(:sidekiq_concurrency_limit_scope_unattributed_jobs_total,
            'Count of jobs of a scoped worker that count against no scope, bound only by the worker limit.')
        end

        def defer_job!
          job['deferred'] = true
          job['deferred_by'] = :concurrency_limit

          ::Gitlab::SidekiqLogging::ConcurrencyLimitLogger.instance.deferred_log(job)
          WorkerHooks.deferred(worker_class, job)

          concurrency_service.add_to_queue!(
            job,
            current_context
          )
        end

        def current_context
          ::Gitlab::ApplicationContext.current
        end

        def disabled_for_worker?
          Feature.enabled?(
            :"disable_sidekiq_concurrency_limit_middleware_#{worker_name}", # rubocop:disable Gitlab/FeatureFlagKeyDynamic -- need to check against worker name dynamically
            Feature.current_request,
            type: :worker,
            default_enabled_if_undefined: false
          )
        end
      end
    end
  end
end
