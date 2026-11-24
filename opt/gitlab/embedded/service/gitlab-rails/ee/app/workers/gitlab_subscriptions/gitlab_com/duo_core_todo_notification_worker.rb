# frozen_string_literal: true

module GitlabSubscriptions
  module GitlabCom
    class DuoCoreTodoNotificationWorker
      include ApplicationWorker

      deduplicate :until_executed, including_scheduled: true
      data_consistency :delayed
      idempotent!
      defer_on_database_health_signal :gitlab_main_org, [:todos], 1.minute

      feature_category :acquisition

      def perform(namespace_id)
        namespace = Namespace.find_by_id(namespace_id)

        return unless namespace&.duo_core_features_enabled? && todo_notifications_enabled?

        todo_service = TodoService.new

        # This is inline with how the group settings area filters eligible users for other types of duo on the
        # seat utilization page.
        users = GitlabSubscriptions::AddOnEligibleUsersFinder.new(namespace, add_on_type: :duo_core).execute

        users.find_in_batches do |batch|
          break unless todo_notifications_enabled? && duo_core_features_enabled_uncached?(namespace)

          todo_service.duo_core_access_granted(batch)
        end
      end

      private

      def todo_notifications_enabled?
        Feature.reset

        Feature.enabled?(:process_duo_core_todo_notifications, :instance, type: :ops)
      end

      def duo_core_features_enabled_uncached?(namespace)
        Namespace.uncached { !!Namespace.find_by_id(namespace.id)&.duo_core_features_enabled? }
      end
    end
  end
end
