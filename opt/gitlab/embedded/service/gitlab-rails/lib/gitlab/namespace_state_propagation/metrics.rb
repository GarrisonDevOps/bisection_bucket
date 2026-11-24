# frozen_string_literal: true

module Gitlab
  module NamespaceStatePropagation
    # Prometheus metrics for namespace state propagation.
    #
    # See doc/development/namespaces_state_propagation.md#metrics
    class Metrics
      DURATION_BUCKETS = [0.1, 0.5, 1, 5, 15, 30, 60, 120, 300, 600, 1800].freeze

      class << self
        def observe_duration(target_state, seconds)
          duration_histogram.observe({ target_state: target_state.to_s }, seconds)
        end

        def increment_batches(target_state)
          batches_counter.increment(target_state: target_state.to_s)
        end

        def increment_boundary_rewinds
          boundary_rewinds_counter.increment
        end

        def increment_failures(target_state)
          failures_counter.increment(target_state: target_state.to_s)
        end

        def increment_stuck_processing(count)
          stuck_processing_counter.increment({}, count)
        end

        def increment_stale_pending(count)
          stale_pending_counter.increment({}, count)
        end

        # Alerts use increase() on these counters, which ignores a series' first
        # sample. Creating them at boot lets the first real increment count.
        def initialize_reconciliation_counters
          stuck_processing_counter.increment({}, 0)
          stale_pending_counter.increment({}, 0)
        end

        def update_outbox_gauges
          counts = ::Namespaces::StatePropagation.counts_by_status

          pending_gauge.set({}, counts.fetch('pending', 0))
          processing_gauge.set({}, counts.fetch('processing', 0))
        end

        def duration_histogram
          Gitlab::Metrics.histogram(
            :gitlab_namespaces_state_propagation_duration_seconds,
            'Time spent propagating a namespace state to its descendants, in seconds',
            {},
            DURATION_BUCKETS
          )
        end

        def batches_counter
          Gitlab::Metrics.counter(
            :gitlab_namespaces_state_propagation_batches_total,
            'Number of descendant batches processed by namespace state propagation'
          )
        end

        def boundary_rewinds_counter
          Gitlab::Metrics.counter(
            :gitlab_namespaces_state_propagation_boundary_rewinds_total,
            'Number of times the state propagation iterator rewound its cursor past a boundary'
          )
        end

        def failures_counter
          Gitlab::Metrics.counter(
            :gitlab_namespaces_state_propagation_failures_total,
            'Number of namespace state propagation runs that raised an error'
          )
        end

        def stuck_processing_counter
          Gitlab::Metrics.counter(
            :gitlab_namespaces_state_propagation_stuck_processing_total,
            'Number of processing namespace state propagation outbox records reset after exceeding the stuck threshold'
          )
        end

        def stale_pending_counter
          Gitlab::Metrics.counter(
            :gitlab_namespaces_state_propagation_stale_pending_total,
            'Number of pending namespace state propagation outbox records older than the stale threshold, ' \
              'counted on every reconciliation run'
          )
        end

        # The counts are table-wide, so `:max` avoids summing them across processes.
        # No mode reports only the latest write, so a process that last refreshed
        # the gauges keeps its value until it refreshes again or restarts.
        def pending_gauge
          Gitlab::Metrics.gauge(
            :gitlab_namespaces_state_propagation_pending_records,
            'Number of pending namespace state propagation outbox records',
            {},
            :max
          )
        end

        def processing_gauge
          Gitlab::Metrics.gauge(
            :gitlab_namespaces_state_propagation_processing_records,
            'Number of processing namespace state propagation outbox records',
            {},
            :max
          )
        end
      end
    end
  end
end
