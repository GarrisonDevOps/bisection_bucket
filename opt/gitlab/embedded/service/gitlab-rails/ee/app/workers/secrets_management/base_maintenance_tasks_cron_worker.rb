# frozen_string_literal: true

module SecretsManagement
  # Shared cron logic for retrying stale `*SecretsManagerMaintenanceTask` rows.
  # Subclasses must implement `maintenance_task_class`, `provision_worker_class`,
  # and `deprovision_worker_class`.
  class BaseMaintenanceTasksCronWorker
    include ApplicationWorker
    include CronjobQueue
    include EachBatch

    data_consistency :sticky
    idempotent!
    feature_category :secrets_management

    BATCH_SIZE = 100
    STALE_THRESHOLD = 5.minutes
    MAX_RETRIES = 3

    def perform
      return if Gitlab::Database.read_only?

      retry_failed_tasks
    end

    private

    def retry_failed_tasks
      maintenance_task_class
        .processable(STALE_THRESHOLD)
        .retryable(MAX_RETRIES)
        .limit(BATCH_SIZE)
        .each_batch do |batch|
          # rubocop:disable CodeReuse/ActiveRecord -- the context resolves root_namespace.full_path per row
          tasks = batch.preload(root_namespace: :route)
          # rubocop:enable CodeReuse/ActiveRecord

          tasks.each do |task|
            with_context(namespace: task.root_namespace) { retry_task_with_isolation(task) }
          end
        end
    end

    # Isolate per-task failures so one bad row (transient DB error on
    # `update!`, a Redis blip on `perform_async`, etc.) can't abort the
    # rest of the batch and stall recovery until the next cron tick.
    def retry_task_with_isolation(task)
      retry_task(task)
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(
        e,
        worker: self.class.name,
        task_class: task.class.name,
        task_id: task.id
      )
    end

    def retry_task(task)
      Gitlab::AppLogger.warn(
        message: "Retrying failed secrets_manager maintenance task",
        task_class: task.class.name,
        task_id: task.id,
        retry_count: task.retry_count,
        stale_duration: task.last_processed_at && (Time.current - task.last_processed_at)
      )

      task.update!(
        last_processed_at: Time.current,
        retry_count: task.retry_count + 1
      )

      worker_for(task).perform_async(task.id)
    end

    def worker_for(task)
      case task.action
      when 'provision'
        provision_worker_class
      when 'deprovision'
        deprovision_worker_class
      else
        raise ArgumentError, "Unsupported maintenance task action: #{task.action.inspect}"
      end
    end

    # Must be implemented by subclasses.
    def maintenance_task_class
      raise NotImplementedError
    end

    def provision_worker_class
      raise NotImplementedError
    end

    def deprovision_worker_class
      raise NotImplementedError
    end
  end
end
