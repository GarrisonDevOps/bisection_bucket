# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    class CleanupWorker
      include ApplicationWorker
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- Context unnecessary

      data_consistency :sticky
      feature_category :subscription_management
      idempotent!

      BATCH_SIZE = 100

      def perform
        GitlabSubscriptions::AddOnPurchase
          .for_seat_assignable_duo_add_ons
          .has_assigned_users
          .ready_for_cleanup
          .includes(:assigned_users, :namespace) # rubocop:disable CodeReuse/ActiveRecord -- Avoid N+1 queries
          .each_batch do |add_on_purchases|
            add_on_purchases.each do |add_on_purchase|
              assigned_users = add_on_purchase.assigned_users
              count = assigned_users.count

              assigned_users.each_batch(of: BATCH_SIZE) do |user_add_on_assigments|
                log_deletion(add_on_purchase, user_add_on_assigments.pluck_user_ids)
                user_add_on_assigments.destroy_all # rubocop:disable Cop/DestroyAll -- https://gitlab.com/gitlab-org/gitlab/-/merge_requests/171331#note_2189629294
              end

              log_summary(add_on_purchase, count) if count > 0
            end
          end
      end

      private

      def log_deletion(add_on_purchase, user_ids)
        Gitlab::AppLogger.info(
          **shared_log_attributes(add_on_purchase).merge(
            message: 'CleanupWorker destroyed UserAddOnAssignments',
            user_ids: user_ids
          )
        )
      end

      def log_summary(add_on_purchase, deleted_assigned_users_count)
        Gitlab::AppLogger.info(
          **shared_log_attributes(add_on_purchase).merge(
            message: 'CleanupWorker UserAddOnAssignments deletion summary',
            user_add_on_assignments_count: deleted_assigned_users_count
          )
        )
      end

      def shared_log_attributes(add_on_purchase)
        {
          add_on: GitlabSubscriptions::SystemDefined::AddOn.name_for_uid(add_on_purchase.subscription_add_on_uid),
          add_on_purchase: add_on_purchase.id,
          namespace: add_on_purchase.namespace&.path
        }
      end
    end
  end
end
