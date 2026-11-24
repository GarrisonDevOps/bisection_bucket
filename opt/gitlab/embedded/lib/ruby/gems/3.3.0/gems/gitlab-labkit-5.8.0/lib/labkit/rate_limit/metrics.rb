# frozen_string_literal: true

require "concurrent-ruby"

module Labkit
  module RateLimit
    module Metrics
      # Process-wide once-latch for log_failure; specs reset via make_false.
      FAILURE_LOGGED = Concurrent::AtomicBoolean.new(false)

      module_function

      # Metric emission must never affect the caller's outcome. Resolving the
      # metric by name keeps a raising getter inside the rescue.
      def safe_increment(counter, labels, logger: nil)
        public_send(counter).increment(**labels) # rubocop:disable GitlabSecurity/PublicSend
      rescue StandardError => e
        log_failure(e, counter, labels, logger)
      end

      # Gauge counterpart of safe_increment.
      def safe_set(gauge, labels, value, logger: nil)
        public_send(gauge).set(labels, value) # rubocop:disable GitlabSecurity/PublicSend
      rescue StandardError => e
        log_failure(e, gauge, labels, logger)
      end

      # make_true returns true only for the flipping caller, so exactly one
      # warn per process. Never raises - a raise here would defeat the
      # callers' rescues.
      def log_failure(error, metric, labels, logger)
        return unless logger && FAILURE_LOGGED.make_true

        logger.warn(
          name: labels[:rate_limiter],
          metric: metric.to_s,
          Labkit::Fields::ERROR_TYPE => "rate_limit_metrics_error",
          Labkit::Fields::CLASS_NAME => error.class.to_s,
          Labkit::Fields::ERROR_MESSAGE => error.message
        )
      rescue StandardError
        nil
      end

      # Emitted exactly once per #check call, including calls that fail open;
      # summing by rate_limiter gives the request rate through the limiter.
      def checks_total
        Labkit::Metrics::Client.counter(
          :gitlab_labkit_rate_limiter_checks_total,
          'Total number of rate limit checks',
          { rate_limiter: nil, action: nil, matched: nil, error: nil }
        )
      end

      # Emitted exactly once per #peek call, including calls that fail open.
      def peeks_total
        Labkit::Metrics::Client.counter(
          :gitlab_labkit_rate_limiter_peeks_total,
          'Total number of rate limit peeks',
          { rate_limiter: nil, error: nil }
        )
      end

      # Emitted once per *evaluated* rule. Only matched rules are evaluated:
      # Unmatched traffic is checks_total{matched="false"}
      def rule_evaluations_total
        Labkit::Metrics::Client.counter(
          :gitlab_labkit_rate_limiter_rule_evaluations_total,
          'Total number of rate limit rule evaluations',
          { rate_limiter: nil, rule: nil, action: nil, result: nil }
        )
      end

      def limit_gauge
        Labkit::Metrics::Client.gauge(
          :gitlab_labkit_rate_limiter_limit,
          'The configured rate limit threshold',
          { rate_limiter: nil, rule: nil },
          :max
        )
      end

      def period_gauge
        Labkit::Metrics::Client.gauge(
          :gitlab_labkit_rate_limiter_period_seconds,
          'The configured rate limit period in seconds',
          { rate_limiter: nil, rule: nil },
          :max
        )
      end
    end
  end
end
