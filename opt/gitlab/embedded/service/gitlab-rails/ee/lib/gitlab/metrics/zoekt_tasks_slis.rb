# frozen_string_literal: true

module Gitlab
  module Metrics
    module ZoektTasksSlis
      include Gitlab::Metrics::SliConfig

      puma_enabled!
      sidekiq_enabled!

      APDEX_THRESHOLD_S = 7200 # 2 hours

      # An exact 60 edge is required: a quantile interpolated across a bucket
      # straddling 60s cannot settle whether a 60s objective was met.

      # 7200 is an exact edge too, so the Apdex ratio stays re-derivable, with
      # `le=~"7200(\\.0+)?"`, never `le="7200"`.
      DURATION_BUCKETS = [1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, 7200, 21600].freeze

      # The queue-wait edges coincide with DURATION_BUCKETS today and are
      # declared separately, not aliased: re-tuning the total-duration edges
      # must not silently move the queue-wait ones.
      QUEUE_DURATION_BUCKETS = [1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, 7200, 21600].freeze
      # Denser below a second than the queue-wait set, because nearly all tasks
      # index in under one and would otherwise land in a single bucket.
      PROCESSING_DURATION_BUCKETS = [0.1, 0.5, 1, 5, 10, 30, 60, 300, 900, 1800, 3600].freeze

      class << self
        def initialize_slis!
          Gitlab::Metrics::Sli::Apdex.initialize_sli(:search_zoekt_tasks, [])
          Gitlab::Metrics::Sli::ErrorRate.initialize_sli(:search_zoekt_tasks, [])
        end

        def increment_request_count(zoekt_node_id:, task_type:, count: 1)
          labels = { zoekt_node: zoekt_node_id.to_s, task_type: task_type.to_s }
          request_counter.increment(labels, count)
        end

        def increment_error_count(zoekt_node_id:, task_type:)
          labels = { zoekt_node: zoekt_node_id.to_s, task_type: task_type.to_s }
          Gitlab::Metrics::Sli::ErrorRate[:search_zoekt_tasks].increment(
            labels: labels,
            error: true
          )
        end

        # queue_wait and processing are both nil whenever no start instant was
        # derivable. They are logged only as a pair, so a line carrying
        # duration_s and no queue_wait_s reads as a skip rather than a zero.
        def increment_apdex(zoekt_node_id:, task_type:, duration:, queue_wait: nil, processing: nil)
          labels = { zoekt_node: zoekt_node_id.to_s, task_type: task_type.to_s }
          success = duration <= APDEX_THRESHOLD_S

          Gitlab::Metrics::Sli::Apdex[:search_zoekt_tasks].increment(
            labels: labels,
            success: success
          )

          observe_floored(duration_histogram, labels, duration)

          payload = {
            message: "Zoekt task Apdex SLI",
            ::Labkit::Fields::DURATION_S => duration,
            target_s: APDEX_THRESHOLD_S,
            success: success,
            zoekt_node: labels[:zoekt_node],
            task_type: labels[:task_type]
          }
          payload.merge!(queue_wait_s: queue_wait, processing_s: processing) if queue_wait && processing

          Gitlab::AppJsonLogger.info(**payload)
        end

        def observe_queue_duration(zoekt_node_id:, task_type:, duration:)
          labels = { zoekt_node: zoekt_node_id.to_s, task_type: task_type.to_s }
          observe_floored(queue_duration_histogram, labels, duration)
        end

        def observe_processing_duration(zoekt_node_id:, task_type:, duration:)
          labels = { zoekt_node: zoekt_node_id.to_s, task_type: task_type.to_s }
          observe_floored(processing_duration_histogram, labels, duration)
        end

        private

        # A retry rewrites `perform_at` into the future, so a callback can
        # compute a negative interval, and a negative observation decrements the
        # histogram's `_sum`. Floored once here, so the three cannot drift.
        def observe_floored(histogram, labels, duration)
          histogram.observe(labels, [duration, 0].max)
        end

        def queue_duration_histogram
          Gitlab::Metrics.histogram(
            :gitlab_search_zoekt_task_queue_duration_seconds,
            'Duration in seconds that a Zoekt task was queued before a node claimed it',
            {},
            QUEUE_DURATION_BUCKETS
          )
        end

        def processing_duration_histogram
          Gitlab::Metrics.histogram(
            :gitlab_search_zoekt_task_processing_duration_seconds,
            'Duration in seconds from a Zoekt task being claimed to its completion callback',
            {},
            PROCESSING_DURATION_BUCKETS
          )
        end

        def request_counter
          @request_counter ||= Gitlab::Metrics.counter(
            :gitlab_sli_search_zoekt_tasks_requests_total,
            'Total number of Zoekt tasks added to the queue'
          )
        end

        # Not memoized: the registration example can only assert the buckets
        # if every call re-enters Gitlab::Metrics.histogram, and
        # Labkit::Metrics::Registry#safe_register already memoizes under a
        # mutex. Matches audit_event_streaming_slis.rb.
        def duration_histogram
          Gitlab::Metrics.histogram(
            :gitlab_search_zoekt_task_duration_seconds,
            "Seconds between a Zoekt task's scheduled time and its completion",
            {},
            DURATION_BUCKETS
          )
        end
      end
    end
  end
end
