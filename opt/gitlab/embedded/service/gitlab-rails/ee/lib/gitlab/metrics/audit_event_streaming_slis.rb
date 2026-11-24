# frozen_string_literal: true

module Gitlab
  module Metrics
    # Metrics for the NATS audit event streaming pipeline (gitlab-org/gitlab#604455).
    #
    # Signals:
    #   - publish degradation (plain counters): how often a publish fell back
    #     to the Sidekiq path. This is deliberately NOT an error-rate SLI: a
    #     fallback still delivers the audit event through Sidekiq, so counting
    #     it as an error would drain the Compliance error budget during shadow
    #     mode and any window where NATS is off or degraded, even though no
    #     event was lost. Track it as a degradation ratio (fallbacks/attempts)
    #     instead. Fires from the request path (Puma) and audit worker (Sidekiq).
    #   - dispatch error rate (SLI): batch deliveries to external destinations
    #     that failed vs. succeeded. A failure here is a genuine delivery
    #     failure, so it is a real error budget signal. Fires from the consumer
    #     worker (Sidekiq).
    #   - dispatch lag apdex (SLI) + raw histogram: publish-to-dispatch latency
    #     scored against a target, plus a histogram for quantiles (p50/p95/p99)
    #     that an apdex ratio cannot express. Fires from the consumer worker.
    #   - delivery outcomes (plain counter): every delivery to an external
    #     destination by category, outcome (success, internal_error,
    #     destination_error) and error category. Fires from the audit worker
    #     (Sidekiq) and the consumer worker.
    #   - delivery duration (plain histogram): wall time of each stream call to
    #     an external destination, by category and outcome. Fires from the
    #     audit worker (Sidekiq) and the consumer worker.
    #   - fetch lag (plain histogram): each message's age when the consumer
    #     fetches it, including redeliveries, so messages that keep failing
    #     still report their age. Fires from the consumer worker.
    #
    # initialize_slis! pre-creates every metric's label set at boot, so rate()
    # alerts and dashboard panels read zero on a healthy fleet instead of "no
    # data" until the first event. The dispatch SLI feeds the runbooks metrics
    # catalog / error budgets once a catalog entry is added. The publish
    # counters are plain metrics (not gitlab_sli_*), so they are outside the
    # error-budget machinery by design.
    module AuditEventStreamingSlis
      include Gitlab::Metrics::SliConfig

      # Publish fires from the request path (Puma) and the audit worker
      # (Sidekiq), so both runtimes pre-initialize the publish counters;
      # dispatch and lag fire from the consumer worker (Sidekiq).
      puma_enabled!
      sidekiq_enabled!

      DISPATCH_SLI = :audit_event_streaming_nats_dispatch

      # Plain counters (deliberately no gitlab_sli_ prefix, which is reserved
      # for the SLI framework's total/error series): a fallback still delivers
      # via Sidekiq, so it is a degradation ratio, not an error-budget signal.
      PUBLISH_COUNTER = :gitlab_audit_event_streaming_nats_publish_total
      FALLBACK_COUNTER = :gitlab_audit_event_streaming_nats_publish_fallback_total
      # Consumer-side unreachability, which fallbacks (producer-side) do not
      # cover when only the Sidekiq fleet is partitioned off from NATS.
      CONSUMER_UNREACHABLE_COUNTER = :gitlab_audit_event_streaming_nats_consumer_unreachable_total
      # Dispatches that failed only because of a destination-side error, tracked
      # as degradation rather than a dispatch SLI error (see record_dispatch_destination_error).
      DISPATCH_DESTINATION_ERROR_COUNTER = :gitlab_audit_event_streaming_nats_dispatch_destination_error_total
      PERMANENT_FAILURE_EVENTS_COUNTER = :gitlab_audit_event_streaming_nats_permanent_failure_events_total
      # Messages whose last allowed delivery failed, so JetStream stops redelivering them.
      MAX_DELIVERIES_COUNTER = :gitlab_audit_event_streaming_nats_max_deliveries_total
      LAG_HISTOGRAM = :gitlab_audit_event_streaming_nats_consumer_lag_seconds
      FETCH_LAG_HISTOGRAM = :gitlab_audit_event_streaming_nats_consumer_fetch_lag_seconds
      # Wall time the synchronous publish blocks the calling Puma/Sidekiq
      # thread, so we can see caller latency, not just the fallback count.
      PUBLISH_DURATION_HISTOGRAM = :gitlab_audit_event_streaming_nats_publish_duration_seconds
      # Deliveries to customer destinations on both the Sidekiq and NATS paths,
      # recorded from BaseStreamDestination#record_delivery. One increment per
      # audit event per destination per attempt, not per unique audit event: a
      # NATS redelivery counts again for destinations that already accepted the
      # batch. A plain counter: a failing customer destination is degradation,
      # not an error-budget signal.
      # HTTP and GCP destinations record a non-2xx response as success until
      # the audit_event_streaming_fail_on_non_2xx_response flag is enabled.
      DELIVERY_COUNTER = :gitlab_audit_event_streaming_deliveries_total
      DELIVERY_DURATION_HISTOGRAM = :gitlab_audit_event_streaming_delivery_duration_seconds
      # Audit events not sent because their destination's circuit was open,
      # recorded from CircuitBreaker.reject_open before destination filters run.
      # A redelivered NATS batch counts again, and with NATS shadow mode on both
      # paths run, so skips count twice.
      DELIVERIES_SKIPPED_COUNTER = :gitlab_audit_event_streaming_circuit_breaker_deliveries_skipped_total
      CIRCUIT_BREAKER_SCOPES = %w[group instance].freeze
      CIRCUIT_BREAKER_DELIVERY_MODES = %w[per_event batched].freeze

      # Buckets in seconds. The scheduler cron floor is one minute, but a
      # backlog can push dispatch lag well past that, so buckets span
      # sub-second to 30 minutes to keep the tail quantifiable under load.
      LAG_BUCKETS = [0.5, 1, 5, 15, 30, 60, 120, 300, 600, 900, 1800].freeze
      # Redelivered messages can be hours old, up to the stream's 24h max_age.
      FETCH_LAG_BUCKETS = [*LAG_BUCKETS, 3600, 7200, 21_600, 43_200, 86_400].freeze
      # Healthy publishes are sub-second; the tail is bounded by the publish
      # timeout plus connect retries.
      PUBLISH_DURATION_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5].freeze
      # Buckets above the 8s HTTP timeout baseline the S3/GCP tail (30s to five
      # minutes) before those timeouts are cut to 8s as well, see
      # https://gitlab.com/gitlab-org/gitlab/-/work_items/636583
      DELIVERY_DURATION_BUCKETS = [0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8, 16, 30, 60, 120, 300].freeze

      # Apdex target: a dispatch is "satisfactory" when publish-to-dispatch
      # lag is at or below this. Set above the scheduler cron floor (one
      # minute) to allow for drain and batch dispatch time before a dispatch
      # counts as unsatisfactory.
      LAG_APDEX_TARGET_SECONDS = 300

      LABELS = { feature_category: :audit_events }.freeze

      # Bounded set of reasons a publish fell back to Sidekiq, kept small so the
      # fallback counter's cardinality stays fixed (never the raw exception
      # message or class). See EnqueueService for how each is classified.
      FALLBACK_REASONS = %i[timeout connection_lost server_error unexpected].freeze

      class << self
        def initialize_slis!
          Gitlab::Metrics::Sli::ErrorRate.initialize_sli(DISPATCH_SLI, [LABELS])
          Gitlab::Metrics::Sli::Apdex.initialize_sli(DISPATCH_SLI, [LABELS])

          # Pre-create the plain counters at zero so their series exist before
          # the first publish (the SLI framework does this automatically for
          # the dispatch SLI; plain counters need an explicit zero increment).
          publish_counter.increment(LABELS, 0)
          consumer_unreachable_counter.increment(LABELS, 0)
          dispatch_destination_error_counter.increment(LABELS, 0)
          # One fallback series per reason so every reason reads zero on a
          # healthy fleet instead of "no data" until the first fallback.
          FALLBACK_REASONS.each { |reason| fallback_counter.increment(LABELS.merge(reason: reason), 0) }

          initialize_delivery_metrics! if Gitlab::Runtime.sidekiq?
        end

        # @param category [String] a Destinations::BY_CATEGORY key
        # @param outcome [Symbol] :success, :internal_error or :destination_error
        # @param error_category [Symbol] a BaseStreamDestination::ERROR_CATEGORIES member, or :none on success
        # @param count [Integer] audit events carried by the delivery
        # @return [void]
        def record_delivery(category:, outcome:, error_category:, count:)
          delivery_counter.increment(delivery_labels(category, outcome, error_category), count)
          nil
        end

        # @param category [String] a Destinations::BY_CATEGORY key
        # @param outcome [Symbol] :success, :internal_error or :destination_error
        # @param seconds [Float, nil] wall time of one stream call; nil when nothing was measured
        # @return [void]
        def observe_delivery_duration(category:, outcome:, seconds:)
          return unless seconds

          delivery_duration_histogram.observe(LABELS.merge(destination_category: category, outcome: outcome), seconds)
        end

        def record_deliveries_skipped(scope:, category:, delivery_mode:, count:)
          deliveries_skipped_counter.increment(skipped_labels(scope, category, delivery_mode), count)
        end

        # Records one publish attempt, and (when it fell back) one fallback
        # labelled with why. The fallback/attempt ratio is a degradation
        # signal, not an error.
        #
        # @param fallback [Boolean] whether the publish fell back to Sidekiq
        #   (NATS publish was not acknowledged).
        # @param reason [Symbol, nil] one of FALLBACK_REASONS; used when
        #   fallback is true (defaults to :unexpected).
        # @return [void]
        def record_publish(fallback:, reason: nil)
          publish_counter.increment(LABELS)
          return unless fallback

          reason = :unexpected unless FALLBACK_REASONS.include?(reason)
          fallback_counter.increment(LABELS.merge(reason: reason))
        end

        # @param seconds [Float] wall time the synchronous publish blocked the
        #   calling thread (recorded whether it succeeded or fell back).
        # @return [void]
        def record_publish_duration(seconds)
          return unless seconds && seconds >= 0

          publish_duration_histogram.observe(LABELS, seconds)
        end

        # @return [void]
        def record_consumer_unreachable
          consumer_unreachable_counter.increment(LABELS)
        end

        # @param result [:success, :failure] outcome of dispatching one group's
        #   batch. Per-group and per-partition detail belongs in structured logs
        #   (the consumer worker logs it); the SLI is a plain success ratio.
        # @return [void]
        def record_dispatch(result:)
          Gitlab::Metrics::Sli::ErrorRate[DISPATCH_SLI].increment(
            labels: LABELS,
            error: result == :failure
          )
        end

        # A dispatch that failed only because of a destination-side error.
        # Recorded separately from the dispatch SLI (degradation, not an error
        # budget signal); the batch is still redelivered.
        # @return [void]
        def record_dispatch_destination_error
          dispatch_destination_error_counter.increment(LABELS)
        end

        # Events a destination will not receive: its failure was permanent, so
        # the batch was acked instead of redelivered.
        #
        # @param destination_category [String, Symbol] http, aws or gcp
        # @param error_category [Symbol] a permanent error category
        # @param event_count [Integer] events in the batch sent to the destination
        # @return [void]
        def record_permanent_failure(destination_category:, error_category:, event_count:)
          permanent_failure_events_counter.increment(
            LABELS.merge(destination_category: destination_category.to_s, error_category: error_category.to_s),
            event_count
          )
        end

        # A message whose last allowed delivery failed. JetStream stops
        # redelivering it, and it stays readable by stream sequence until max_age.
        #
        # @param consumer [String] durable consumer name
        # @return [void]
        def record_max_delivery(consumer:)
          max_deliveries_counter.increment(LABELS.merge(consumer: consumer))
        end

        # @param seconds [Float] time between publish and dispatch (consumer lag)
        # @return [void]
        def observe_lag(seconds)
          return unless seconds

          if seconds < 0
            # Clock skew between the publishing and consuming hosts (NTP drift)
            # can produce a negative lag. Drop it from the metrics but leave a
            # breadcrumb rather than hiding it entirely.
            Gitlab::AppJsonLogger.debug(
              ::Labkit::Fields::CLASS_NAME => name,
              message: 'Dropping negative audit event streaming lag',
              lag_seconds: seconds
            )
            return
          end

          lag_histogram.observe(LABELS, seconds)
          dispatch_lag_apdex.increment(labels: LABELS, success: seconds <= LAG_APDEX_TARGET_SECONDS)
        end

        # @param seconds [Float] time between publish and the consumer fetching
        #   the message, on every delivery
        # @param redelivered [Boolean] whether the message was delivered before
        # @return [void]
        def observe_fetch_lag(seconds, redelivered:)
          # Negative values are clock skew between hosts; dropped.
          return unless seconds && seconds >= 0

          fetch_lag_histogram.observe(LABELS.merge(redelivered: redelivered.to_s), seconds)
        end

        def dispatch_error_rate
          Gitlab::Metrics::Sli::ErrorRate[DISPATCH_SLI]
        end

        def dispatch_lag_apdex
          Gitlab::Metrics::Sli::Apdex[DISPATCH_SLI]
        end

        def publish_counter
          Gitlab::Metrics.counter(PUBLISH_COUNTER, 'Total number of audit event publish attempts through NATS')
        end

        def fallback_counter
          Gitlab::Metrics.counter(
            FALLBACK_COUNTER,
            'Total number of audit event publishes that fell back from NATS to Sidekiq'
          )
        end

        def consumer_unreachable_counter
          Gitlab::Metrics.counter(
            CONSUMER_UNREACHABLE_COUNTER,
            'Total number of audit event consumer drains aborted because NATS was unreachable'
          )
        end

        def dispatch_destination_error_counter
          Gitlab::Metrics.counter(
            DISPATCH_DESTINATION_ERROR_COUNTER,
            'Total number of audit event batch dispatches that failed due to a destination-side error'
          )
        end

        def permanent_failure_events_counter
          Gitlab::Metrics.counter(
            PERMANENT_FAILURE_EVENTS_COUNTER,
            'Total number of audit events not delivered to a destination because of a permanent failure'
          )
        end

        def max_deliveries_counter
          Gitlab::Metrics.counter(
            MAX_DELIVERIES_COUNTER,
            'Total number of audit event NATS messages whose last allowed delivery failed'
          )
        end

        def publish_duration_histogram
          Gitlab::Metrics.histogram(
            PUBLISH_DURATION_HISTOGRAM,
            'Audit event streaming NATS synchronous publish duration in seconds',
            {},
            PUBLISH_DURATION_BUCKETS
          )
        end

        def fetch_lag_histogram
          Gitlab::Metrics.histogram(
            FETCH_LAG_HISTOGRAM,
            'Audit event streaming NATS message age at fetch in seconds, including redeliveries',
            {},
            FETCH_LAG_BUCKETS
          )
        end

        def lag_histogram
          Gitlab::Metrics.histogram(
            LAG_HISTOGRAM,
            'Audit event streaming NATS consumer lag (publish to dispatch) in seconds',
            {},
            LAG_BUCKETS
          )
        end

        def delivery_counter
          Gitlab::Metrics.counter(
            DELIVERY_COUNTER,
            'Deliveries to external streaming destinations by outcome, ' \
              'one per audit event per destination per attempt, not unique audit events'
          )
        end

        def delivery_duration_histogram
          Gitlab::Metrics.histogram(
            DELIVERY_DURATION_HISTOGRAM,
            'Audit event streaming delivery duration per destination call in seconds',
            {},
            DELIVERY_DURATION_BUCKETS
          )
        end

        def deliveries_skipped_counter
          Gitlab::Metrics.counter(
            DELIVERIES_SKIPPED_COUNTER,
            'Total number of audit events not sent to a streaming destination because its circuit breaker was open'
          )
        end

        def skipped_labels(scope, category, delivery_mode)
          LABELS.merge(scope: scope, destination_category: category, delivery_mode: delivery_mode)
        end

        def initialize_delivery_metrics!
          ::AuditEvents::Streaming::Destinations::BY_CATEGORY.each_key do |category|
            delivery_error_categories_by_outcome.each do |outcome, error_categories|
              error_categories.each do |error_category|
                delivery_counter.increment(delivery_labels(category, outcome, error_category), 0)
              end
            end

            CIRCUIT_BREAKER_SCOPES.each do |scope|
              CIRCUIT_BREAKER_DELIVERY_MODES.each do |delivery_mode|
                deliveries_skipped_counter.increment(skipped_labels(scope, category, delivery_mode), 0)
              end
            end
          end
        end

        def delivery_error_categories_by_outcome
          error_categories = ::AuditEvents::Streaming::Destinations::BaseStreamDestination::ERROR_CATEGORIES

          {
            success: [:none],
            internal_error: [:internal_error],
            destination_error: error_categories - [:internal_error]
          }
        end

        def delivery_labels(category, outcome, error_category)
          LABELS.merge(destination_category: category, outcome: outcome, error_category: error_category)
        end
      end
    end
  end
end
