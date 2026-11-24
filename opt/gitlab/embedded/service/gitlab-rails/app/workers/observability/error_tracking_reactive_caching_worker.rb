# frozen_string_literal: true

module Observability
  # Refreshes Sentry error tracking cache entries on their own class, so a burst
  # of them cannot exhaust the concurrency shared by other external dependency
  # reactive caches (Jira, environments, clusters, Prometheus).
  class ErrorTrackingReactiveCachingWorker < ExternalServiceReactiveCachingWorker # rubocop:disable Scalability/IdempotentWorker -- Also disabled for parent worker
    CONCURRENCY_LIMIT = 20

    feature_category :observability

    concurrency_limit -> { CONCURRENCY_LIMIT }
  end
end
