# frozen_string_literal: true

module SecretsManagement
  module GroupSecretsManagers
    # See {InitiateDeprovisionServiceHelpers} for the shared flow.
    # Destroys the group secrets manager row; the AFTER DELETE trigger
    # installed by gitlab-org/gitlab#600290 inserts the deprovision
    # maintenance task using the SM's denormalized snapshot ids.
    class InitiateDeprovisionService
      include InitiateDeprovisionServiceHelpers

      # `group_id` is required for the SM-gone gate: when the SM row has
      # already been CASCADE-deleted but a deprovision task is still
      # pending, the helper needs the group id to check the task table.
      def initialize(secrets_manager, user = nil, group_id:)
        @secrets_manager = secrets_manager
        @current_user = user
        @group_id = group_id
      end

      private

      attr_reader :group_id

      def not_found_message
        'Secrets manager not found for the group.'
      end

      def success_payload
        { group_secrets_manager: secrets_manager }
      end

      def pending_deprovision_task_without_sm?
        SecretsManagement::GroupSecretsManagerMaintenanceTask.deprovision_pending_for?(group_id)
      end

      def lookup_pending_deprovision_task
        SecretsManagement::GroupSecretsManagerMaintenanceTask
          .find_by(group_id: secrets_manager.group_id, action: :deprovision) # rubocop:disable CodeReuse/ActiveRecord -- single-row lookup, no scope warranted
      end

      def enqueue_deprovision_worker(task)
        SecretsManagement::DeprovisionGroupSecretsManagerWorker.perform_async(task.id)
      end

      class << self
        # Bulk-destroys active group secrets managers under
        # `groups_relation`. Each row deletion fires the AFTER DELETE
        # trigger, which inserts a deprovision maintenance task using
        # the SM's denormalized snapshot ids. No `perform_async`: cron
        # picks the rows up within ~1 minute via the `:unprocessed`
        # scope. See gitlab-org/gitlab#600290.
        # rubocop:disable CodeReuse/ActiveRecord -- bulk SM destroy scoped to subtree
        def bulk_initiate_for_groups(groups_relation)
          ::SecretsManagement::GroupSecretsManager
            .where(status: ::SecretsManagement::BaseSecretsManager::STATUSES[:active])
            .where(group_id: groups_relation)
            .delete_all
        end
        # rubocop:enable CodeReuse/ActiveRecord
      end
    end
  end
end
