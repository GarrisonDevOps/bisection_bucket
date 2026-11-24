# frozen_string_literal: true

module SecretsManagement
  class DeprovisionProjectSecretsManagerWorker
    include ApplicationWorker

    data_consistency :sticky

    urgency :low

    worker_has_external_dependencies!

    defer_on_database_health_signal :gitlab_main_org, [:project_secrets_managers], 1.minute

    idempotent!

    feature_category :secrets_management

    # The maintenance task is the single source of truth for retries:
    # `ProjectSecretsManagerMaintenanceTasksCronWorker` re-enqueues it up to `MAX_RETRIES`.
    # Sidekiq's own retries would run on a parallel clock on top of that.
    sidekiq_options retry: false

    def perform(maintenance_task_id)
      task = ProjectSecretsManagerMaintenanceTask.find_by_id(maintenance_task_id)
      return unless task

      # `user_id` can be NULL for tasks created by the post-DELETE
      # trigger on `project_secrets_managers`, where no current_user is
      # available. Downstream code (BaseDeprovisionService +
      # GlobalSecretsManagerJwt) treats a nil user as a system context.
      user = task.user_id ? User.find_by_id(task.user_id) : nil

      ProjectSecretsManagers::DeprovisionService.new(task, user).execute
    end
  end
end
