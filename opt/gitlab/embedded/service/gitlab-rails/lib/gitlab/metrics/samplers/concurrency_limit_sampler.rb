# frozen_string_literal: true

module Gitlab
  module Metrics
    module Samplers
      class ConcurrencyLimitSampler < BaseSampler
        include ExclusiveLeaseGuard

        # Scrape timing explanation:
        # - Prometheus scrapes occur every 1 minute
        # - Our sampler lease lasts for 5 minutes
        # - After writing metrics, we sleep for 30s until lease expires before resetting the metrics to 0.
        DEFAULT_SAMPLING_INTERVAL_SECONDS = 30
        LEASE_TIMEOUT = 300
        DURATION_BUCKETS = [0.1, 0.5, 1, 5, 15, 30, 60, 120, 300].freeze

        # One process per Redis shard and queue list reports while holding the lease.
        # The previous holder resets its metrics so scrapes use the new holder's values.
        def sample
          try_obtain_lease do
            # Keep reporting the metrics while the lease is valid
            # to ensure we have continuous data. Also check if the
            # sampler is still running because a SIGTERM will cause
            # the sleep to be interrupted and the loop to run again
            # until the condition is false.
            while running && exclusive_lease.same_uuid?
              start = ::Gitlab::Metrics::System.monotonic_time
              report_metrics
              duration_metric.observe({}, ::Gitlab::Metrics::System.monotonic_time - start)

              # Ensure that we don't sleep if the state changed
              # after reporting metrics.
              break unless running

              Kernel.sleep(DEFAULT_SAMPLING_INTERVAL_SECONDS)
            end

            # Reset metrics to ensure only the next sample reports fresh data.
            reset_metrics
          end
        end

        private

        # Used by ExclusiveLeaseGuard
        def lease_timeout
          LEASE_TIMEOUT
        end

        def lease_key
          # rubocop:disable Cop/RedisQueueUsage -- Reading the shard-name constant does not access queue Redis.
          shard = ENV.fetch('SIDEKIQ_SHARD_NAME', Gitlab::Redis::Queues::SIDEKIQ_MAIN_SHARD_INSTANCE_NAME)
          # rubocop:enable Cop/RedisQueueUsage
          "#{self.class.name.underscore}:shard:#{shard}:queues:#{current_queues.join(',')}"
        end

        def lease_taken_log_level
          :info
        end

        def report_metrics
          workers.each do |w|
            queue_size = concurrent_limit_service.queue_size(w.name)
            report_queue_size(w, queue_size)

            concurrent_worker_count = concurrent_limit_service.concurrent_worker_count(w.name)
            report_concurrent_workers(w, concurrent_worker_count)

            max_limit = w.get_concurrency_limit
            report_max_limit(w, max_limit)
            Gitlab::SidekiqMiddleware::ConcurrencyLimit::EnqueueLimit.publish(w, max_limit)

            current_limit = concurrent_limit_service.current_limit(w.name)
            report_current_limit(w, current_limit)

            override_limit = concurrent_limit_service.override_status(w.name)[:limit]
            report_override_limit(w, override_limit || 0)
          end
        end

        def reset_metrics
          workers.each do |w|
            report_queue_size(w, 0)
            report_concurrent_workers(w, 0)
            report_max_limit(w, 0)
            report_current_limit(w, 0)
            report_override_limit(w, 0)
          end
        end

        def workers
          @workers ||= Gitlab::SidekiqConfig
                         .workers_without_default
                         .select do |worker|
                           queue = ::Gitlab::SidekiqConfig::WorkerRouter.global.route(worker.klass)
                           current_queues.include?(queue)
                         end
                         .map(&:klass)
        end

        def current_queues
          Sidekiq.default_configuration.queues
        end

        def concurrent_limit_service
          Gitlab::SidekiqMiddleware::ConcurrencyLimit::ConcurrencyLimitService
        end

        def duration_metric
          @duration_metric ||= Gitlab::Metrics.histogram(:sidekiq_concurrency_limit_sampler_duration_seconds,
            'Time to report the concurrency limit metrics of every worker on the shard.', {}, DURATION_BUCKETS)
        end

        def report_queue_size(worker, queue_size)
          @queue_size_metric ||= Gitlab::Metrics.gauge(:sidekiq_concurrency_limit_queue_jobs,
            'Number of jobs queued by the concurrency limit middleware.')
          @queue_size_metric.set({ worker: worker.name, feature_category: worker.get_feature_category }, queue_size)
        end

        def report_concurrent_workers(worker, concurrent_worker_count)
          @concurrency_metric ||= Gitlab::Metrics.gauge(:sidekiq_concurrency_limit_current_concurrent_jobs,
            'Current number of concurrent running jobs.')
          @concurrency_metric.set({ worker: worker.name, feature_category: worker.get_feature_category },
            concurrent_worker_count)
        end

        def report_max_limit(worker, limit)
          @limit_metric ||= Gitlab::Metrics.gauge(:sidekiq_concurrency_limit_max_concurrent_jobs,
            'Max number of concurrent running jobs.')
          @limit_metric.set({ worker: worker.name, feature_category: worker.get_feature_category }, limit)
        end

        def report_current_limit(worker, limit)
          @current_limit_metric ||= Gitlab::Metrics.gauge(:sidekiq_concurrency_limit_current_limit,
            'Number of concurrent jobs currently allowed to run subject to throttling.')
          @current_limit_metric.set({ worker: worker.name, feature_category: worker.get_feature_category }, limit)
        end

        def report_override_limit(worker, limit)
          @override_limit_metric ||= Gitlab::Metrics.gauge(:sidekiq_concurrency_limit_override_limit,
            'Operator override of the concurrency limit. Zero when no override is active.')
          @override_limit_metric.set({ worker: worker.name, feature_category: worker.get_feature_category }, limit)
        end
      end
    end
  end
end
