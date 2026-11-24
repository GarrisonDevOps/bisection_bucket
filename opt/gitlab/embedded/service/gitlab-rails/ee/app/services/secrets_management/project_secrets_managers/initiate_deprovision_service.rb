# frozen_string_literal: true

module SecretsManagement
  module ProjectSecretsManagers
    # See {InitiateDeprovisionServiceHelpers} for the shared flow.
    # Destroys the project secrets manager row; the AFTER DELETE
    # trigger installed by gitlab-org/gitlab#600290 inserts the
    # deprovision maintenance task using the SM's denormalized
    # snapshot ids.
    class InitiateDeprovisionService
      include InitiateDeprovisionServiceHelpers

      # `project_id` is required for the SM-gone gate: when the SM row
      # has already been CASCADE-deleted but a deprovision task is still
      # pending, the helper needs the project id to check the task table.
      def initialize(secrets_manager, user = nil, project_id:)
        @secrets_manager = secrets_manager
        @current_user = user
        @project_id = project_id
      end

      private

      attr_reader :project_id

      def not_found_message
        'Secrets manager not found for the project.'
      end

      def success_payload
        { project_secrets_manager: secrets_manager }
      end

      def pending_deprovision_task_without_sm?
        SecretsManagement::ProjectSecretsManagerMaintenanceTask.deprovision_pending_for?(project_id)
      end

      # Look up the task the trigger just inserted. We need the row to
      # `perform_async` against; the trigger runs inside the same
      # transaction as `destroy!`, so by this point the INSERT is
      # visible to our session.
      def lookup_pending_deprovision_task
        SecretsManagement::ProjectSecretsManagerMaintenanceTask
          .find_by(project_id: secrets_manager.project_id, action: :deprovision) # rubocop:disable CodeReuse/ActiveRecord -- single-row lookup, no scope warranted
      end

      def enqueue_deprovision_worker(task)
        SecretsManagement::DeprovisionProjectSecretsManagerWorker.perform_async(task.id)
      end

      class << self
        # Bulk-destroys active project secrets managers under
        # `projects_relation`. Each row deletion fires the AFTER DELETE
        # trigger, which inserts a deprovision maintenance task using
        # the SM's denormalized snapshot ids. No `perform_async`: the
        # caller is the group transfer hook, which runs inside the
        # transfer transaction; the cron picks up the tasks within ~1
        # minute via the `:unprocessed` scope (`last_processed_at IS
        # NULL`). See gitlab-org/gitlab#600290.
        # rubocop:disable CodeReuse/ActiveRecord -- bulk SM destroy scoped to subtree
        def bulk_initiate_for_projects(projects_relation)
          ::SecretsManagement::ProjectSecretsManager
            .where(status: ::SecretsManagement::BaseSecretsManager::STATUSES[:active])
            .where(project_id: projects_relation)
            .delete_all
        end
        # rubocop:enable CodeReuse/ActiveRecord
      end
    end
  end
end
