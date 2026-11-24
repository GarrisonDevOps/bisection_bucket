# frozen_string_literal: true

module Security
  module DependencyFirewall
    class FlushPreventedPackagesWriteBufferCronWorker
      include ApplicationWorker
      include LoopWithRuntimeLimit
      include Gitlab::ExclusiveLeaseHelpers

      idempotent!
      # Not CronjobQueue: that forces retry: false, and a failed flush should be retried.
      queue_namespace :cronjob
      data_consistency :sticky
      feature_category :dependency_firewall

      MAX_RUNTIME = 200.seconds
      BATCH_SIZE = 1000
      # Not renewed mid-run, so it must outlast MAX_RUNTIME plus an overshooting batch.
      LOCK_TTL = 10.minutes
      InvalidEnumValueError = ::Security::DependencyFirewallPreventedPackage::InvalidEnumValueError

      def perform
        flushed_entries = 0
        discarded_entries = 0
        remaining_entries = 0
        status = nil

        in_lock(self.class.name.underscore, ttl: LOCK_TTL, retries: 0) do
          write_buffer.stage!

          cursor = '0'

          status = loop_with_runtime_limit(MAX_RUNTIME) do |runtime_limiter|
            entries, cursor = write_buffer.staged_batch(BATCH_SIZE, cursor)

            # A page can exceed the COUNT hint, so slice to keep each upsert at BATCH_SIZE rows.
            entries.each_slice(BATCH_SIZE) do |slice|
              break if runtime_limiter.over_time?

              flushed, discarded = flush(slice, runtime_limiter)
              flushed_entries += flushed
              discarded_entries += discarded
            end

            break :processed if cursor == '0'
          end

          remaining_entries = write_buffer.staged_size
        end

        log_extra_metadata_on_done(:result, {
          status: status,
          flushed_entries: flushed_entries,
          discarded_entries: discarded_entries,
          remaining_entries: remaining_entries,
          buffered_entries: write_buffer.live_size
        })
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
        log_extra_metadata_on_done(:result, {
          status: :lease_taken,
          flushed_entries: 0,
          discarded_entries: 0,
          remaining_entries: write_buffer.staged_size,
          buffered_entries: write_buffer.live_size
        })
      end

      private

      # Clearing only after the write commits: a crash in between re-applies the batch next run,
      # which the LEAST/GREATEST merge absorbs, whereas clearing first loses it if COMMIT fails.
      # A single poison row must degrade to per-row flushing, not wedge the staged batch forever.
      def flush(entries, runtime_limiter)
        ledger_model.transaction { ledger_model.bulk_upsert!(entries.map(&:to_row)) }
        write_buffer.remove_staged(entries)
        schedule_group_refreshes(entries)

        [entries.size, 0]
      rescue ActiveRecord::StatementInvalid, InvalidEnumValueError => e
        raise unless poison_entry_error?(e)

        flush_entries_individually(entries, runtime_limiter)
      end

      # A dead reference or constraint-violating entry fails every retry; PostgreSQL arbitrates
      # each row and poison entries are discarded.
      def flush_entries_individually(entries, runtime_limiter)
        flushed = 0
        discarded = 0
        committed_entries = []

        entries.each do |entry|
          break if runtime_limiter.over_time?

          ledger_model.transaction { ledger_model.bulk_upsert!([entry.to_row]) }
          write_buffer.remove_staged([entry])

          committed_entries << entry
          flushed += 1
        rescue ActiveRecord::StatementInvalid, InvalidEnumValueError => e
          raise unless poison_entry_error?(e)

          write_buffer.remove_staged([entry])
          log_discarded_entry(entry)

          discarded += 1
        end

        [flushed, discarded]
      ensure
        schedule_group_refreshes(committed_entries)
      end

      def schedule_group_refreshes(entries)
        return if entries.empty?

        group_ids = ::Security::DependencyFirewall::PreventedStats::AffectedGroups
          .for_projects(entries.map(&:project_id).uniq)
        ::Security::DependencyFirewall::RefreshGroupPreventedStatsWorker.schedule(group_ids)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e)
      end

      # Only failures a retry can never fix, including enum values this version does not map.
      # Timeouts, deadlocks and lost connections are also StatementInvalid, and must re-raise so
      # Sidekiq retries with the entries still staged.
      def poison_entry_error?(error)
        error.is_a?(ActiveRecord::InvalidForeignKey) ||
          error.is_a?(InvalidEnumValueError) ||
          error.cause.is_a?(PG::CheckViolation)
      end

      def log_discarded_entry(entry)
        logger.warn(
          structured_payload(
            message: 'Discarded prevented-package ledger entry that cannot be persisted',
            project_id: entry.project_id,
            rule_type: entry.rule_type
          )
        )
      end

      def write_buffer
        ledger_model.write_buffer
      end

      def ledger_model
        ::Security::DependencyFirewallPreventedPackage
      end
    end
  end
end
