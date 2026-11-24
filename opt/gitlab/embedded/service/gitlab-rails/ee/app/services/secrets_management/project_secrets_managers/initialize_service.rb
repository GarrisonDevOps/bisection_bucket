# frozen_string_literal: true

module SecretsManagement
  module ProjectSecretsManagers
    class InitializeService < ProjectBaseService
      include InitializeServiceHelpers

      private

      def resource
        project
      end

      def ensure_secrets_manager_allowed_on_resource
        if resource.namespace.user_namespace?
          return ServiceResponse.error(message: 'Secrets manager is not available for projects in user namespaces.')
        end

        ServiceResponse.success
      end

      def deprovision_in_progress?
        ProjectSecretsManagerMaintenanceTask.deprovision_pending_for?(project.id)
      end

      def create_secrets_manager
        ProjectSecretsManager.create!(project: project)
      end

      def create_maintenance_task(_secrets_manager)
        ProjectSecretsManagerMaintenanceTask.create!(
          user: current_user,
          project_id: project.id,
          organization_id: project.organization_id,
          root_namespace_id: project.root_ancestor.id,
          action: :provision,
          # Set to NOW() so the cron's stale scope (`< STALE_THRESHOLD.ago`)
          # skips this row until `perform_async` below runs. The cron is the
          # recovery path for failed/abandoned tasks, not the primary processor.
          last_processed_at: Time.zone.now
        )
      end

      def enqueue_provision_worker(task)
        ProvisionProjectSecretsManagerTaskWorker.perform_async(task.id)
      end

      def track_enabled_event
        track_internal_event(
          'enable_ci_secrets_manager_for_project',
          project: project,
          namespace: project.namespace,
          user: current_user
        )
      end
    end
  end
end
