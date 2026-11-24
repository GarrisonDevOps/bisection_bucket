# frozen_string_literal: true

module SecretsManagement
  module GroupSecretsManagers
    class InitializeService < GroupBaseService
      include InitializeServiceHelpers

      private

      def resource
        group
      end

      def create_secrets_manager
        GroupSecretsManager.create!(group: group)
      end

      def create_maintenance_task(_secrets_manager)
        GroupSecretsManagerMaintenanceTask.create!(
          user: current_user,
          group_id: group.id,
          organization_id: group.organization_id,
          root_namespace_id: group.root_ancestor.id,
          action: :provision,
          # Set to NOW() so the cron's stale scope (`< STALE_THRESHOLD.ago`)
          # skips this row until `perform_async` below runs. The cron is the
          # recovery path for failed/abandoned tasks, not the primary processor.
          last_processed_at: Time.zone.now
        )
      end

      def enqueue_provision_worker(task)
        ProvisionGroupSecretsManagerTaskWorker.perform_async(task.id)
      end

      def deprovision_in_progress?
        GroupSecretsManagerMaintenanceTask.deprovision_pending_for?(group.id)
      end

      def track_enabled_event
        track_internal_event('enable_ci_secrets_manager_for_group', namespace: group, user: current_user)
      end
    end
  end
end
