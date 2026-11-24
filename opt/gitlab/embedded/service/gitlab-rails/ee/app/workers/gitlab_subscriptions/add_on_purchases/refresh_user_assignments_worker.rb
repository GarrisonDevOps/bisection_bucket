# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    class RefreshUserAssignmentsWorker
      include ::ApplicationWorker
      include Gitlab::ExclusiveLeaseHelpers

      LEASE_TTL = 3.minutes

      feature_category :seat_cost_management

      data_consistency :sticky
      urgency :low

      deduplicate :until_executed, if_deduplicated: :reschedule_once
      idempotent!

      def perform(root_namespace_id)
        @root_namespace_id = root_namespace_id

        return unless add_on_purchase

        deleted_assignments_count = 0
        in_lock(add_on_purchase.lock_key_for_refreshing_user_assignments, ttl: LEASE_TTL, retries: 0) do
          deleted_assignments_count += add_on_purchase.delete_ineligible_user_assignments_in_batches!

          reconcile_response = GitlabSubscriptions::AddOnPurchases::ReconcileSeatOverageService.new(
            add_on_purchase: add_on_purchase.reset
          ).execute
          deleted_assignments_count += reconcile_response.payload[:removed_seats_count]
        end

        # #update_column used to skip validations and callbacks.
        #
        # See https://api.rubyonrails.org/v7.0.8/classes/ActiveRecord/Persistence.html#method-i-update_columns
        # for more information.
        add_on_purchase.update_column(:last_assigned_users_refreshed_at, Time.current)

        log_event(deleted_assignments_count) if deleted_assignments_count > 0
      end

      private

      attr_reader :root_namespace_id

      def add_on_purchase
        @add_on_purchase ||= GitlabSubscriptions::Duo.enterprise_or_pro_for_namespace(root_namespace_id)
      end

      def log_event(deleted_count)
        Gitlab::AppLogger.info(
          message: 'AddOnPurchase user assignments refreshed in bulk',
          deleted_assignments_count: deleted_count,
          add_on: add_on_purchase.add_on.name,
          add_on_purchase_id: add_on_purchase.id,
          namespace_id: root_namespace_id
        )
      end
    end
  end
end
