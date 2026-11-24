# frozen_string_literal: true

module Security
  class PurgeScansService
    include Gitlab::Utils::StrongMemoize

    MAX_STALE_SCANS_SIZE = 200_000

    # Each worker invocation is deliberately short-lived. A run purges in batches from the
    # persisted keyset cursor until it either drains the stale set, hits MAX_STALE_SCANS_SIZE,
    # or exceeds MAX_RUNTIME. Keeping runs well under Sidekiq/deploy interrupt limits means an
    # interrupted run simply resumes from the cursor on the next invocation. A large backlog is
    # drained by back-to-back short runs (see Security::Scans::PurgeWorker self-re-enqueue),
    # not by one long-lived job.
    MAX_RUNTIME = 3.minutes

    # Batch size is modulated by database health when the health-check flag is enabled:
    # healthy runs use MAX_BATCH_SIZE; under moderate pressure the run uses MIN_BATCH_SIZE and
    # applies a small backoff sleep between batches. A run that starts under pressure and a run
    # that starts healthy re-probe independently, so the batch size ramps back up across runs
    # once the database recovers. With the flag disabled the batch size is fixed at
    # MAX_BATCH_SIZE (the previous SCAN_BATCH_SIZE) and no health is evaluated, so behaviour is
    # unchanged.
    MAX_BATCH_SIZE = 100
    MIN_BATCH_SIZE = 10
    SCAN_BATCH_SIZE = MAX_BATCH_SIZE

    # Under moderate pressure we pause briefly between batches. Kept short so the run stays
    # within MAX_RUNTIME and never holds a database connection idle for long.
    MODERATE_PRESSURE_SLEEP = 0.1

    # Evaluating database health issues queries, so we only re-evaluate every
    # HEALTH_CHECK_INTERVAL batches to bound the cost while still reacting within a run.
    HEALTH_CHECK_INTERVAL = 10

    # To optimise purging against rereading dead tuples on progressive purge executions
    # we cache the last purged tuple so that the next job can start where the prior finished.
    # The TTL comfortably outlives the cron cadence so cursor progress survives across the
    # many short runs it takes to drain a large backlog, rather than resetting to the head.
    LAST_PURGED_SCAN_TUPLE = 'Security::PurgeScansService::LAST_PURGED_SCAN_TUPLE'
    LAST_PURGED_SCAN_TUPLE_TTL = 8.days

    # Tables touched (directly or by cascade) when scans are purged and their findings
    # are subsequently reaped. We check these for active autovacuum so we yield when the
    # database is already busy maintaining them.
    HEALTH_CHECK_TABLES = %w[security_scans security_findings].freeze

    DATABASE_TABLE_HEALTH_INDICATORS = [
      Gitlab::Database::HealthStatus::Indicators::AutovacuumActiveOnTable
    ].freeze
    GLOBAL_DATABASE_HEALTH_INDICATORS = [
      Gitlab::Database::HealthStatus::Indicators::WriteAheadLog,
      Gitlab::Database::HealthStatus::Indicators::PatroniApdex
    ].freeze

    DatabaseHealthStatusChecker = Struct.new(:id, :job_class_name)

    # Outcome of a run, consumed by the worker to decide whether to re-enqueue.
    #  - :drained         the stale set was exhausted; nothing to re-enqueue.
    #  - :work_remaining  the run stopped on a bound (runtime/count) with stale work left.
    #  - :halted          health signalled a hard stop mid-run; do not re-enqueue this tick.
    #  - :unhealthy       the pre-run health gate tripped; the run did not start.
    Result = Data.define(:status, :updated_count) do
      def re_enqueue?
        status == :work_remaining
      end
    end

    class << self
      def purge_stale_records
        return Result.new(status: :unhealthy, updated_count: 0) if database_unhealthy?

        execute(Security::Scan.stale.ordered_by_created_at_and_id, redis_cursor.cursor, persist_cursor: true)
      end

      # Event-driven purges must not write the shared cursor. Their scans are not ordered
      # with the stale set, so a write would move the stale cron past unpurged scans.
      def purge_by_build_ids(build_ids)
        Security::Scan.by_build_ids(build_ids).then { |relation| execute(relation) }
      end

      def execute(security_scans, cursor = {}, persist_cursor: false)
        new(security_scans, cursor, persist_cursor: persist_cursor).execute
      end

      def redis_cursor
        @redis_cursor ||= Gitlab::Redis::CursorStore.new(LAST_PURGED_SCAN_TUPLE, ttl: LAST_PURGED_SCAN_TUPLE_TTL)
      end

      # Coarse pre-run gate. When the health-check flag is enabled we consult
      # Gitlab::Database::HealthStatus (the same primitive that throttles batched background
      # migrations) and skip the run entirely when any indicator signals a stop. When the flag
      # is disabled the previous, unconditional behaviour is preserved.
      def database_unhealthy?
        return false unless health_check_enabled?

        evaluate_health.any?(&:stop?)
      end

      # Evaluate the configured health indicators once.
      def evaluate_health
        health_context = Gitlab::Database::HealthStatus::Context.new(
          DatabaseHealthStatusChecker.new(nil, name),
          Security::Scan.connection,
          HEALTH_CHECK_TABLES
        )

        indicators = DATABASE_TABLE_HEALTH_INDICATORS + GLOBAL_DATABASE_HEALTH_INDICATORS

        Gitlab::Database::HealthStatus.evaluate(health_context, indicators)
      end

      # This is an instance-wide operational toggle for a global cron worker, so there
      # is no meaningful feature actor to scope it to.
      # rubocop:disable Gitlab/FeatureFlagWithoutActor -- instance-wide ops flag for a cron worker
      def health_check_enabled?
        Feature.enabled?(:security_scans_purge_db_health_check, type: :ops)
      end
      # rubocop:enable Gitlab/FeatureFlagWithoutActor
    end

    def initialize(security_scans, cursor = {}, persist_cursor: false)
      @security_scans = security_scans
      @iterator = Gitlab::Pagination::Keyset::Iterator.new(scope: security_scans, cursor: cursor)
      @persist_cursor = persist_cursor
      @updated_count = 0
      @runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)
      @batches_processed = 0
      @halted = false
      @drained = false
    end

    def execute
      # Effective batch size and pacing are decided once per run from the current health
      # policy. A run under moderate pressure shrinks the batch and paces itself; the next run
      # re-probes and ramps back up when the database has recovered.
      policy = run_policy
      @batch_size = policy[:batch_size]
      @sleep_seconds = policy[:sleep_seconds]

      # If the whole each_batch block completes without an early break, the stale set has been
      # exhausted (the iterator breaks when no rows remain) and there is nothing to re-enqueue.
      @drained = true

      iterator.each_batch(of: @batch_size) do |batch|
        last_updated_record = batch.last

        @updated_count += purge(batch)

        # Persist the cursor *before* any early break so progress is never lost, even on a
        # health-triggered hard stop or a runtime break.
        store_last_purged_tuple(last_updated_record.created_at, last_updated_record.id) if last_updated_record

        @batches_processed += 1

        if @updated_count >= MAX_STALE_SCANS_SIZE || runtime_limiter.over_time?
          @drained = false
          break
        end

        # Consult health periodically to modulate this run. On a hard stop we bail cleanly
        # (cursor already persisted above) and do not re-enqueue.
        if health_hard_stop?
          @halted = true
          @drained = false
          break
        end

        pace_between_batches
      end

      reset_cursor if @drained

      result
    end

    private

    attr_reader :iterator, :security_scans, :runtime_limiter

    # rubocop:disable CodeReuse/ActiveRecord -- id-scoped bulk update is intentional; see below
    def purge(scan_batch)
      # update_all ignores LIMIT on the keyset batch relation, so calling it on the relation
      # directly would purge every stale scan from the cursor onward in a single statement,
      # defeating the per-batch runtime and count bounds. Restrict the update to this batch's
      # rows via a bounded id subquery (the batch relation is already LIMIT-ed to @batch_size,
      # so the subquery is bounded and no unbounded pluck is materialised).
      Security::Scan.where(id: scan_batch.select(:id)).update_all(status: :purged)
    end
    # rubocop:enable CodeReuse/ActiveRecord

    # Decide the batch size + inter-batch sleep for this run from the current health policy.
    # No health query (and no modulation) when the flag is disabled.
    def run_policy
      return { batch_size: MAX_BATCH_SIZE, sleep_seconds: 0 } unless self.class.health_check_enabled?

      health_policy(self.class.evaluate_health)
    end

    # Periodically re-evaluate health mid-run and report whether we must hard-stop. No-op (and
    # no health query) when the flag is disabled, preserving the original behaviour.
    def health_hard_stop?
      return false unless self.class.health_check_enabled?
      return false unless (@batches_processed % HEALTH_CHECK_INTERVAL) == 0

      self.class.evaluate_health.any?(&:stop?)
    end

    # Small, testable policy mapping evaluated health signals to a run shape.
    #  - any stop signal        -> a run would immediately hard-stop; use MIN_BATCH_SIZE.
    #  - any non-normal signal  -> moderate pressure: shrink batch + brief backoff.
    #  - all normal             -> full batch, no sleep.
    def health_policy(signals)
      return { batch_size: MIN_BATCH_SIZE, sleep_seconds: 0 } if signals.any?(&:stop?)

      if signals.any? { |signal| !signal.is_a?(Gitlab::Database::HealthStatus::Signals::Normal) }
        return { batch_size: MIN_BATCH_SIZE, sleep_seconds: MODERATE_PRESSURE_SLEEP }
      end

      { batch_size: MAX_BATCH_SIZE, sleep_seconds: 0 }
    end

    # Brief backoff between batches under moderate pressure. The pause is intentionally tiny
    # (MODERATE_PRESSURE_SLEEP) so we never hold a database connection idle for a meaningful
    # length of time; a longer pause would risk pinning a pool slot, so instead of sleeping
    # longer the run simply ends early and the cursor + re-enqueue/cron continue it later.
    def pace_between_batches
      return unless @sleep_seconds > 0

      sleep(@sleep_seconds)
    end

    def result
      status =
        if @halted
          :halted
        elsif @drained
          :drained
        else
          :work_remaining
        end

      Result.new(status: status, updated_count: @updated_count)
    end

    # Normal to string methods for dates don't include the split seconds that rails usually includes in queries.
    # Without them, it's possible to still match on the last processed record instead of the one after it.
    def store_last_purged_tuple(created_at, id)
      return unless @persist_cursor

      quoted_time = Security::Scan.connection.quote(created_at)

      self.class.redis_cursor.commit(created_at: quoted_time, id: id)
    end

    # Without this, a cursor that lands past unpurged stale scans strands them, because
    # every later run starts after it and reports :drained.
    def reset_cursor
      return unless @persist_cursor

      self.class.redis_cursor.commit({})
    end
  end
end
