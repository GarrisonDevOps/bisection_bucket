# frozen_string_literal: true

module Ci
  module Runners
    # Trims runners that recently created managers back to ci_max_runner_managers_per_runner. Managers inside the
    # online grace period are never deleted, and deleted ones are recreated on the runner's next request.
    #
    # Each run also records the runners at ci_runner_manager_creation_ceiling in RunnerManagerCreationCeiling, before
    # any deletion and even while deletions pause. Those runners are counted on every run, since they can't create
    # managers and so aren't discovered.
    class RunnerManagerCapService
      # Twice the cron interval, so that a delayed run still sees every runner that created managers since the last one.
      DISCOVERY_WINDOW = 20.minutes
      # Bounds the discovery query and the counts of the runners it finds. Runs log `discovery_limit_reached` when they
      # hit it. Runners at the ceiling are counted too, up to RunnerManagerCreationCeiling::MAX_RUNNERS.
      MAX_RUNNERS_PER_RUN = 3_000
      SUB_BATCH_SIZE = 100
      # Stops before the 300-second apdex target of urgency :low jobs. The next run picks up the rest.
      MAX_RUNTIME = 4.minutes
      # Pending loose foreign key records are counted up to this multiple of the limit for the run's log, so that
      # the limit can be tuned from the logged values.
      LFK_PENDING_LOG_FACTOR = 10

      def initialize
        @runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)
        @lfk_backlog = LooseForeignKeysBacklog.new
        @deleted_count = 0
        @stop_reason = nil
        @discovery_limit_reached = false
      end

      def execute
        return ServiceResponse.success(payload: { skipped: true }) unless enabled?

        lfk_pending_records = lfk_pending_records_for_log
        counts = count_runner_managers
        runners_at_ceiling = record_ceiling(counts, trimming_paused: trimming_paused?(lfk_pending_records))
        runners = runners_over_cap(counts)

        runners.each { |runner, count| trim(runner) if enforce?(runner, count) }

        ServiceResponse.success(payload: {
          runners_over_cap: runners.size,
          runners_at_ceiling: runners_at_ceiling,
          deleted_count: deleted_count,
          stop_reason: stop_reason || (:budget if budget_left <= 0),
          lfk_pending_records: lfk_pending_records,
          discovery_limit_reached: discovery_limit_reached
        }.compact)
      end

      private

      attr_reader :runtime_limiter, :lfk_backlog, :deleted_count, :stop_reason, :discovery_limit_reached

      def enabled?
        cap_enabled? || ceiling_enabled?
      end

      def cap_enabled?
        cap > 0 &&
          (Feature.enabled?(:log_runner_manager_cap, :instance) ||
            Feature.enabled?(:enforce_runner_manager_cap, :instance))
      end

      def ceiling_enabled?
        ceiling > 0 &&
          (Feature.enabled?(:log_runner_manager_cap, :instance) ||
            Feature.enabled?(:enforce_runner_manager_ceiling, :instance))
      end

      # Returns { runner_id => count }. Counts stop one above the larger enabled limit, which is all the checks need.
      # Runners at the ceiling are counted first, so that a run that takes too long still renews their entries.
      # The runners not counted yet are left for the next run.
      def count_runner_managers
        limit = [cap_enabled? ? cap : 0, ceiling_enabled? ? ceiling : 0].max + 1
        counts = {}
        runner_keys = recently_created_runner_keys
        @discovery_limit_reached = runner_keys.size >= MAX_RUNNERS_PER_RUN

        (runner_keys_at_ceiling + runner_keys).uniq.each do |runner_id, runner_type|
          if runtime_limiter.over_time?
            @stop_reason = :runtime
            break
          end

          counts[runner_id] = count_managers(runner_id, runner_type, limit: limit)
        end

        counts
      end

      # Returns the number of runners at or above the ceiling.
      def record_ceiling(counts, trimming_paused:)
        return 0 unless ceiling_enabled?

        reached, cleared = counts.partition { |_runner_id, count| count >= ceiling }.map(&:to_h)

        reached.each do |runner_id, count|
          Gitlab::AppJsonLogger.info(
            Labkit::Fields::CLASS_NAME => self.class.name,
            message: 'Runner manager creation ceiling reached',
            runner_id: runner_id,
            runner_managers_count: count,
            limit: ceiling,
            trimming_paused: trimming_paused
          )
        end

        RunnerManagerCreationCeiling.record(reached_runner_ids: reached.keys, cleared_runner_ids: cleared.keys)

        reached.size
      end

      # When the logged count timed out, decides like stop? does, so that the log doesn't hide a pause.
      def trimming_paused?(lfk_pending_records)
        return lfk_backlog.over_limit?(lfk_pending_limit) if lfk_pending_records.nil?

        lfk_pending_records > lfk_pending_limit
      end

      # Returns [runner, count] pairs above the cap.
      def runners_over_cap(counts)
        return [] unless cap_enabled?

        counts = counts.select { |_runner_id, count| count > cap }
        runners = ::Ci::Runner.id_in(counts.keys).index_by(&:id)

        counts.filter_map { |runner_id, count| [runners[runner_id], count] if runners[runner_id] }
      end

      def count_managers(runner_id, runner_type, limit:)
        ::Ci::RunnerManager.count_for_runner_key(runner_id, runner_type, limit: limit)
      end

      def recently_created_runner_keys
        ::Ci::RunnerManager.runner_keys_created_since(DISCOVERY_WINDOW.ago, limit: MAX_RUNNERS_PER_RUN)
      end

      # Only logged, so a timeout leaves the value out instead of failing the run.
      def lfk_pending_records_for_log
        lfk_backlog.pending_count(limit: lfk_pending_limit * LFK_PENDING_LOG_FACTOR)
      rescue ActiveRecord::QueryCanceled # rubocop:disable Database/RescueQueryCanceled -- the count is only logged
        nil
      end

      def runner_keys_at_ceiling
        return [] unless ceiling_enabled?

        ::Ci::Runner.id_in(RunnerManagerCreationCeiling.runner_ids).map { |runner| [runner.id, runner.runner_type] }
      end

      # Logs whether managers are deleted, not the flag state, so that runners skipped after a stop aren't
      # logged as enforced.
      def enforce?(runner, count)
        enforced = Feature.enabled?(:enforce_runner_manager_cap, runner) && !stop?

        Gitlab::AppJsonLogger.info(
          Labkit::Fields::CLASS_NAME => self.class.name,
          message: 'Runner manager cap exceeded',
          runner_id: runner.id,
          runner_type: runner.runner_type,
          runner_managers_count: count,
          limit: cap,
          enforced: enforced
        )

        enforced
      end

      # Widening the deadline in steps deletes long-idle managers first without sorting the runner's managers.
      def trim(runner)
        # Count no further than this run can delete, so that the count stays bounded by cap + budget.
        excess = count_managers(runner.id, runner.runner_type, limit: cap + budget_left) - cap

        deadlines.each do |deadline|
          excess = trim_not_contacted_since(runner, deadline, excess)
          break if excess <= 0 || stop_reason
        end
      end

      # Returns the excess left after deleting managers not contacted since the deadline.
      def trim_not_contacted_since(runner, deadline, excess)
        while excess > 0 && !stop?
          limit = [SUB_BATCH_SIZE, excess, budget_left].min
          deleted = ::Ci::RunnerManager.delete_not_contacted_since(runner, deadline, limit: limit)
          @deleted_count += deleted
          excess -= deleted

          break if deleted < limit
        end

        excess
      end

      # Stays true once true, so that a backlog that drains mid-run doesn't restart deletions.
      def stop?
        return true if stop_reason

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

      # The last step pads the online timeout like Ci::Runner.recent_queue_deadline, because the database contacted_at
      # is only updated every UPDATE_CONTACT_COLUMN_EVERY and can lag the real last contact.
      def deadlines
        [
          ::Ci::RunnerManager.stale_deadline,
          1.day.ago,
          (::Ci::Runner::ONLINE_CONTACT_TIMEOUT + ::Ci::RunnerManager::UPDATE_CONTACT_COLUMN_EVERY.max).ago
        ]
      end

      def budget_left
        settings.ci_runner_manager_cap_deletions_per_run - deleted_count
      end

      def cap
        settings.ci_max_runner_managers_per_runner
      end

      def ceiling
        settings.ci_runner_manager_creation_ceiling
      end

      def lfk_pending_limit
        settings.ci_runner_manager_cap_cleanup_backlog_limit
      end

      def settings
        Gitlab::CurrentSettings.current_application_settings
      end
    end
  end
end
