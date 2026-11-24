# frozen_string_literal: true

module SecretsManagement
  # Safety-net cron that terminates `*SecretsManagerMaintenanceTask` rows the
  # normal retry cron has given up on. See gitlab-org/gitlab#600120.
  #
  # A task whose `retry_count` has reached `BaseMaintenanceTasksCronWorker::MAX_RETRIES`
  # is excluded from the retry cron's `retryable(MAX_RETRIES)` scope and
  # sits forever. The unique index on `parent_id` means a stuck task also
  # blocks the user from initiating a fresh provision or deprovision for
  # the same parent. The reaper is the post-incident reconciler that
  # unblocks the parent by terminating the stuck row.
  #
  # Terminate = call the same `DeprovisionService` the worker pipeline uses,
  # regardless of the row's `action`. The service tears down whatever
  # OpenBao state exists at the snapshot paths (idempotent, tolerates
  # "route entry not found" and "containing child namespaces"), deletes
  # the SM row if it still exists, and deletes the maintenance task.
  # After this pass the parent has no SM and no task; the user can
  # re-initialize cleanly.
  #
  # The reaper is deliberately blunt: it does not try to distinguish
  # transient outages from permanent failures, nor preserve partially
  # provisioned OpenBao state. Three retries by the retry cron over
  # ~15 minutes are the "is it transient?" gate; anything past that is
  # treated as stuck and cleaned up.
  #
  # Subclasses must implement `maintenance_task_class` and
  # `deprovision_service_class`.
  class BaseReapOrphanTasksCronWorker
    include ApplicationWorker
    include CronjobQueue
    include EachBatch

    data_consistency :sticky
    idempotent!
    feature_category :secrets_management

    BATCH_SIZE = 50

    # Tasks must be at least this old before the reaper acts. Comfortably
    # exceeds `BaseMaintenanceTasksCronWorker::STALE_THRESHOLD` (5 minutes)
    # and `BaseDeprovisionService::LEASE_TIMEOUT` (120 seconds) so the
    # reaper never races a worker about to retry naturally or a stale
    # lease about to expire.
    GRACE_PERIOD = 30.minutes
    MAX_REAP_INTERVAL = 1.day

    def perform
      return if Gitlab::Database.read_only?

      stuck_tasks.each_batch(of: BATCH_SIZE) do |batch|
        # rubocop:disable CodeReuse/ActiveRecord -- the context resolves root_namespace.full_path per row
        tasks = batch.preload(root_namespace: :route)
        # rubocop:enable CodeReuse/ActiveRecord

        tasks.each do |task|
          next unless due_for_reap?(task)

          with_context(namespace: task.root_namespace) { reap_task_with_isolation(task) }
        end
      end
    end

    private

    # rubocop:disable CodeReuse/ActiveRecord -- reaper-specific scope on the per-table task class
    def stuck_tasks
      maintenance_task_class
        .where(retry_count: BaseMaintenanceTasksCronWorker::MAX_RETRIES..)
        .where(last_processed_at: ...GRACE_PERIOD.ago)
    end
    # rubocop:enable CodeReuse/ActiveRecord

    # Each failed reap doubles the wait, up to a day, so a deprovision that keeps failing
    # is retried less often but never given up on. Dropping the task would unblock the parent
    # but leave its OpenBao data behind.
    def due_for_reap?(task)
      failed_reaps = task.retry_count - BaseMaintenanceTasksCronWorker::MAX_RETRIES
      interval = [GRACE_PERIOD * (2**failed_reaps), MAX_REAP_INTERVAL].min

      task.last_processed_at <= interval.ago
    end

    # Isolate per-task failures so one bad row can't abort the rest of the
    # batch and stall recovery until the next reaper tick.
    def reap_task_with_isolation(task)
      reap_task(task)
    rescue StandardError => e
      track_reap_error(e, task)
      record_failed_reap(task)
    end

    def record_failed_reap(task)
      task.update!(last_processed_at: Time.current, retry_count: task.retry_count + 1)
    rescue StandardError => e
      track_reap_error(e, task)
    end

    def track_reap_error(error, task)
      Gitlab::ErrorTracking.track_exception(
        error,
        worker: self.class.name,
        task_class: task.class.name,
        task_id: task.id
      )
    end

    def reap_task(task)
      Gitlab::AppLogger.warn(
        message: 'Reaping stuck secrets manager maintenance task',
        worker: self.class.name,
        task_class: task.class.name,
        task_id: task.id,
        action: task.action,
        retry_count: task.retry_count,
        last_processed_at: task.last_processed_at&.iso8601
      )

      deprovision_service_class.new(task, nil).execute
    end

    def maintenance_task_class
      raise NotImplementedError
    end

    def deprovision_service_class
      raise NotImplementedError
    end
  end
end
