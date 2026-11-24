# frozen_string_literal: true

module SecretsManagement
  # Sentry reporting for fail-open rescues that re-run while a dependency is
  # down. Every occurrence reaches `exceptions_json.log`; Sentry gets one event
  # per call site and error class per window, fleet-wide.
  #
  # Sentry sends in the calling thread (`background_worker_threads` is 0) and its
  # transport allows 1s to connect plus 2s to read, so when a dependency fails
  # fast -- CDot answering HTTP 500 rather than hanging -- an unthrottled report
  # is most of the request's cost, at the highest volume.
  module ThrottledErrorTracking
    REPORT_TTL = 5.minutes
    KEY_PREFIX = 'secrets_management:throttled_error_tracking'

    class << self
      # `throttle_key` names the call site; the error class joins it in the cache
      # key so a new failure mode is never masked by an ongoing one.
      def track_exception(error, throttle_key:, ttl: REPORT_TTL, **extra)
        return ::Gitlab::ErrorTracking.track_exception(error, extra) if claim_window?(throttle_key, error, ttl)

        ::Gitlab::ErrorTracking.log_exception(error, extra)
      end

      private

      # Read-then-write rather than an atomic `unless_exist:`: that cannot tell
      # "another process holds the window" from "Redis is down" -- both come back
      # false, and the second must still report.
      def claim_window?(throttle_key, error, ttl)
        key = [KEY_PREFIX, *throttle_key, error.class.name]
        return false if Rails.cache.exist?(key)

        Rails.cache.write(key, true, expires_in: ttl)
        true
      rescue StandardError
        # Callers are fail-open rescues; a cache fault must not surface as their
        # exception, nor decide that an error goes unreported.
        true
      end
    end
  end
end
