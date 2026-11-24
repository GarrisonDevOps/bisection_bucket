# frozen_string_literal: true

module Authz
  module ProjectAuthorizations
    # Drains authz_refresh_events. The cron run each minute queues one job per slot. The polling slot waits on an
    # empty queue until its runtime limit, so new events wait about a second; the others exit once it's empty, so
    # an idle queue holds one thread. Correctness doesn't depend on how many run.
    class RefreshWorker
      include ApplicationWorker
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- RefreshService sets the context for each lease

      data_consistency :sticky
      feature_category :permissions
      urgency :low
      idempotent!
      # Until executed, so a polling slot can't overlap itself; rescheduling once restarts it right after it ends
      # instead of at the next cron run.
      deduplicate :until_executed, if_deduplicated: :reschedule_once
      concurrency_limit -> { SLOTS }
      # Every indicator but autovacuum, which can run on project_authorizations for hours and would stop every
      # revocation.
      defer_on_database_health_signal :gitlab_main_org, [], 1.minute,
        indicators: Gitlab::Database::HealthStatus::GLOBAL_INDICATORS

      MAX_RUNTIME = 4.minutes
      POLL_INTERVAL = 1.second
      SLOTS = 4
      POLLING_SLOT = 1

      # @param slot [Integer, nil] nil for the cron run, which queues the slots. Deduplication keeps at most
      #   one job per slot queued or running.
      def perform(slot = nil)
        return self.class.bulk_perform_async((1..SLOTS).map { |n| [n] }) unless slot # rubocop:disable Scalability/BulkPerformWithContext -- a slot belongs to no resource; each lease sets its own context

        poll_interval = POLL_INTERVAL if slot == POLLING_SLOT
        result = RefreshService.new(Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME), poll_interval: poll_interval)
          .execute

        result.payload.each { |key, value| log_extra_metadata_on_done(key, value) }
      end
    end
  end
end
