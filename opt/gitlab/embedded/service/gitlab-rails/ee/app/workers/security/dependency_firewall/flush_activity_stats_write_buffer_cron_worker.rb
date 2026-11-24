# frozen_string_literal: true

module Security
  module DependencyFirewall
    class FlushActivityStatsWriteBufferCronWorker
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

      def perform
        flushed_buckets = 0
        discarded_buckets = 0
        remaining_buckets = 0
        status = nil

        in_lock(self.class.name.underscore, ttl: LOCK_TTL, retries: 0) do
          write_buffer.stage!

          status = loop_with_runtime_limit(MAX_RUNTIME) do |runtime_limiter|
            rows = write_buffer.staged_batch(BATCH_SIZE)

            break :processed if rows.empty?

            flushed, discarded = flush(rows, runtime_limiter)
            flushed_buckets += flushed
            discarded_buckets += discarded
          end

          remaining_buckets = write_buffer.staged_size
        end

        log_extra_metadata_on_done(:result, {
          status: status,
          flushed_buckets: flushed_buckets,
          discarded_buckets: discarded_buckets,
          remaining_buckets: remaining_buckets,
          buffered_buckets: write_buffer.live_size
        })
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
        log_extra_metadata_on_done(:result, {
          status: :lease_taken,
          flushed_buckets: 0,
          discarded_buckets: 0,
          remaining_buckets: write_buffer.staged_size,
          buffered_buckets: write_buffer.live_size
        })
      end

      private

      # Clearing inside the transaction so a Redis failure rolls the write back, not the reverse.
      def flush(rows, runtime_limiter)
        stat_model.transaction do
          stat_model.bulk_increment!(rows)
          write_buffer.remove_staged(rows)
        end

        [rows.size, 0]
      rescue ActiveRecord::InvalidForeignKey
        flush_rows_individually(rows, runtime_limiter)
      end

      # A dead reference fails every retry; PostgreSQL arbitrates each row and dead buckets are discarded.
      def flush_rows_individually(rows, runtime_limiter)
        flushed = 0
        discarded = 0

        rows.each do |row|
          break if runtime_limiter.over_time?

          stat_model.transaction do
            stat_model.bulk_increment!([row])
            write_buffer.remove_staged([row])
          end

          flushed += 1
        rescue ActiveRecord::InvalidForeignKey
          write_buffer.remove_staged([row])
          log_discarded_bucket(row)

          discarded += 1
        end

        [flushed, discarded]
      end

      def log_discarded_bucket(row)
        logger.warn(
          structured_payload(message: 'Discarded activity stats bucket with dead references', **row)
        )
      end

      def write_buffer
        stat_model.write_buffer
      end

      def stat_model
        ::Security::DependencyFirewallActivityStat
      end
    end
  end
end
