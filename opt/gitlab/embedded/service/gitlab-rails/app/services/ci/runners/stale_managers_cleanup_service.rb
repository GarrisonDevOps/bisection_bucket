# frozen_string_literal: true

module Ci
  module Runners
    class StaleManagersCleanupService
      MAX_DELETIONS = 1000
      SUB_BATCH_LIMIT = 100
      # Stops before the 300-second apdex target of urgency :low jobs. The next run picks up the rest.
      MAX_RUNTIME = 4.minutes
      # Pending loose foreign key records are counted up to this multiple of the limit for the run's log.
      LFK_PENDING_LOG_FACTOR = 10
      # The cron runs every 10 minutes. Without the feature flag, the lease keeps the previous hourly behavior.
      LEGACY_LEASE_KEY = 'ci:runners:stale_managers_cleanup:legacy'
      LEGACY_INTERVAL = 55.minutes
      CRON_INTERVAL = 10.minutes

      def initialize
        @runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)
        @lfk_backlog = LooseForeignKeysBacklog.new
        @deleted_by_runner_type = ::Ci::RunnerManager.runner_types.keys.index_with(0)
        @stop_reason = nil
      end

      def execute
        unless Feature.enabled?(:stale_runner_manager_cleanup_by_partition, :instance)
          return ServiceResponse.success(payload: { skipped: true }) unless legacy_lease.try_obtain

          return ServiceResponse.success(payload: delete_stale_runner_managers)
        end

        lfk_pending_records = lfk_pending_records_for_log
        delete_by_runner_type

        ServiceResponse.success(payload: {
          total_deleted: deleted_count,
          deleted_by_runner_type: deleted_by_runner_type,
          stop_reason: stop_reason,
          lfk_pending_records: lfk_pending_records
        }.compact)
      end

      private

      attr_reader :runtime_limiter, :lfk_backlog, :deleted_by_runner_type, :stop_reason

      # Takes one batch from each runner type in turn, so that a large backlog in one partition doesn't use up the
      # budget of the others. A runner type leaves the rotation when a batch comes back short. Each cron run starts at
      # the next runner type, so a budget that isn't a multiple of the batch size doesn't favor the first.
      def delete_by_runner_type
        runner_types = deleted_by_runner_type.keys
        runner_types.rotate!((Time.current.to_i / CRON_INTERVAL.to_i) % runner_types.size)

        until runner_types.empty? || stop?
          runner_type = runner_types.shift
          limit = [SUB_BATCH_LIMIT, budget_left].min
          selected, deleted = ::Ci::RunnerManager.delete_stale(runner_type: runner_type, limit: limit)
          deleted_by_runner_type[runner_type] += deleted

          runner_types << runner_type if selected == limit
        end
      end

      def stop?
        @stop_reason =
          if budget_left <= 0
            :budget
          elsif runtime_limiter.over_time?
            :runtime
          elsif lfk_backlog.over_limit?(lfk_pending_limit)
            :loose_foreign_keys
          end

        stop_reason.present?
      end

      # Only logged, so a timeout leaves the value out instead of failing the run.
      def lfk_pending_records_for_log
        lfk_backlog.pending_count(limit: lfk_pending_limit * LFK_PENDING_LOG_FACTOR)
      rescue ActiveRecord::QueryCanceled # rubocop:disable Database/RescueQueryCanceled -- the count is only logged
        nil
      end

      def deleted_count
        deleted_by_runner_type.values.sum
      end

      def budget_left
        settings.ci_stale_runner_managers_cleanup_deletions_per_run - deleted_count
      end

      # Never above the cap's limit, so that this cleanup always stops before the runner manager cap does.
      def lfk_pending_limit
        [
          settings.ci_stale_runner_managers_cleanup_backlog_limit,
          settings.ci_runner_manager_cap_cleanup_backlog_limit
        ].min
      end

      def settings
        Gitlab::CurrentSettings.current_application_settings
      end

      def legacy_lease
        Gitlab::ExclusiveLease.new(LEGACY_LEASE_KEY, timeout: LEGACY_INTERVAL)
      end

      def delete_stale_runner_managers
        batch_counts = []
        total_deleted_count = 0
        loop do
          sub_batch_limit = [SUB_BATCH_LIMIT, MAX_DELETIONS].min

          # delete_all discards part of the `stale` scope query, so we explicitly wrap it with a SELECT as a workaround
          deleted_count = Ci::RunnerManager.id_in(Ci::RunnerManager.stale.limit(sub_batch_limit)).delete_all
          batch_counts << deleted_count
          total_deleted_count += deleted_count

          break if deleted_count == 0 || total_deleted_count >= MAX_DELETIONS
        end

        {
          total_deleted: total_deleted_count,
          batch_counts: batch_counts
        }
      end
    end
  end
end
