# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    class BulkRefreshUserAssignmentsWorker
      include ApplicationWorker
      include LimitedCapacity::Worker
      include Gitlab::ExclusiveLeaseHelpers

      LEASE_TTL = 3.minutes

      feature_category :seat_cost_management
      data_consistency :sticky
      urgency :low

      idempotent!

      MAX_RUNNING_JOBS = 10

      def perform_work
        return unless add_on_purchase

        deleted_assignments_count = 0
        in_lock(add_on_purchase.lock_key_for_refreshing_user_assignments, ttl: LEASE_TTL, retries: 0) do
          deleted_assignments_count = add_on_purchase.delete_ineligible_user_assignments_in_batches!

          reconcile_response = GitlabSubscriptions::AddOnPurchases::ReconcileSeatOverageService.new(
            add_on_purchase: add_on_purchase
          ).execute

          deleted_assignments_count += reconcile_response.payload[:removed_seats_count]
        end

        log_event(deleted_assignments_count) if deleted_assignments_count > 0
      end

      def remaining_work_count(*_args)
        add_on_purchases_requiring_refresh(max_running_jobs + 1).count
      end

      def max_running_jobs
        MAX_RUNNING_JOBS
      end

      private

      def add_on_purchase
        @add_on_purchase ||= find_next_add_on_purchase
      end

      def find_next_add_on_purchase
        GitlabSubscriptions::AddOnPurchase.transaction do
          add_on_purchase = GitlabSubscriptions::AddOnPurchase.next_candidate_requiring_assigned_users_refresh

          next unless add_on_purchase

          add_on_purchase.update_column(:last_assigned_users_refreshed_at, Time.current)

          add_on_purchase
        end
      end

      def add_on_purchases_requiring_refresh(limit = 1)
        GitlabSubscriptions::AddOnPurchase.requiring_assigned_users_refresh(limit)
      end

      def log_event(deleted_count)
        Gitlab::AppLogger.info(
          message: 'AddOnPurchase user assignments refreshed via scheduled CronJob',
          deleted_assignments_count: deleted_count,
          add_on: add_on_purchase.add_on.name,
          namespace: add_on_purchase.namespace&.path
        )
      end
    end
  end
end
