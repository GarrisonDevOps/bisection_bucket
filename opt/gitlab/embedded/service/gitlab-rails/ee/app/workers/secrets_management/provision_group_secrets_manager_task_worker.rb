# frozen_string_literal: true

module SecretsManagement
  # Provisions a group's secrets manager via a maintenance task. Replaces
  # the legacy `ProvisionGroupSecretsManagerWorker` (which takes
  # `(user_id, sm_id)` directly). Going through a maintenance task gives
  # the worker the same crash-recovery story the deprovision flow has
  # had from day one: if this worker dies, the task is left stale and
  # `GroupSecretsManagerMaintenanceTasksCronWorker` retries it.
  class ProvisionGroupSecretsManagerTaskWorker
    include ApplicationWorker

    data_consistency :sticky

    urgency :low

    worker_has_external_dependencies!

    defer_on_database_health_signal :gitlab_main_org, [:group_secrets_managers], 1.minute

    idempotent!

    feature_category :secrets_management

    # The maintenance task is the single source of truth for retries: it
    # tracks `retry_count` and gets re-enqueued by the cron worker after
    # `STALE_THRESHOLD` up to `MAX_RETRIES`. Sidekiq's own retries would
    # run on a parallel clock and not touch `retry_count`, which would
    # let the cron's cap be silently exceeded.
    sidekiq_options retry: false

    def perform(maintenance_task_id)
      task = GroupSecretsManagerMaintenanceTask.find_by_id(maintenance_task_id)
      return unless task && task.provision?

      secrets_manager = task.secrets_manager
      return unless secrets_manager

      user = task.user
      return unless user

      result = GroupSecretsManagers::ProvisionService.new(secrets_manager, user).execute
      task.destroy if result.success?
    end
  end
end
