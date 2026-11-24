# frozen_string_literal: true

module Security
  module Scans
    class PurgeWorker
      include ApplicationWorker
      include Gitlab::ExclusiveLeaseHelpers
      include CronjobQueue # rubocop: disable Scalability/CronWorkerContext

      sidekiq_options retry: false
      feature_category :vulnerability_management
      data_consistency :always

      idempotent!

      # Guards against overlapping runs: a cron tick landing while a re-enqueued chain is
      # mid-run (or vice-versa) must no-op rather than double-purge. Sized to comfortably
      # outlive a single bounded run (MAX_RUNTIME) plus a margin for a long final query, so a
      # crashed run's lease expires and the work becomes available again on the next tick.
      LEASE_TTL = (::Security::PurgeScansService::MAX_RUNTIME + 1.minute).freeze

      # Delay before a self-re-enqueued run continues from the cursor. Small enough to drain a
      # backlog promptly, large enough to avoid a tight enqueue spin.
      RE_ENQUEUE_DELAY = 5.seconds

      def perform
        in_lock(self.class.name.underscore, ttl: LEASE_TTL, retries: 0) do
          result = ::Security::PurgeScansService.purge_stale_records

          log_extra_metadata_on_done(:purge_status, result.status)
          log_extra_metadata_on_done(:purged_count, result.updated_count)

          # Drain a large backlog via back-to-back short runs: if the run stopped on a bound
          # with stale work still remaining, immediately continue from the persisted cursor.
          # We stop re-enqueuing when the set is drained, the database is unhealthy, or a
          # health hard-stop occurred mid-run. The frequent cron schedule is the safety-net
          # restart if a chain ever stops early.
          self.class.perform_in(RE_ENQUEUE_DELAY) if result.re_enqueue?
        end
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
        # Another run holds the lease. Nothing to do: it is already draining the cursor, and a
        # later cron tick will pick up any remaining work. This keeps the worker idempotent.
        Gitlab::AppLogger.info(
          Labkit::Fields::CLASS_NAME => self.class.name,
          message: 'Skipped: another Security::Scans::PurgeWorker run holds the exclusive lease'
        )
      end
    end
  end
end
