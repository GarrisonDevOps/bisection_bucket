# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    class CleanupUserAddOnAssignmentWorker
      include ::ApplicationWorker
      include GitlabSubscriptions::AddOnPurchases::UserAddOnAssignmentCommon

      feature_category :seat_cost_management

      data_consistency :sticky
      urgency :low

      deduplicate :until_executed, if_deduplicated: :reschedule_once
      idempotent!

      def perform(root_namespace_id, user_id)
        @root_namespace_id = root_namespace_id
        @user_id           = user_id

        return unless root_namespace && user && add_on_purchase && assignment

        return if eligible_for_seat?

        assignment.destroy!

        Rails.cache.delete(::Ai::UserAuthorizer.duo_pro_cache_key_formatted(user_id))

        log_event
      end

      private

      attr_reader :user_id, :root_namespace_id

      def eligible_for_seat?
        root_namespace.eligible_for_gitlab_duo_pro_seat?(user)
      end

      def log_event
        Gitlab::AppLogger.info(
          message: 'CleanupUserAddOnAssignmentWorker destroyed UserAddOnAssignment',
          user: user.username.to_s,
          user_id: user_id,
          add_on: add_on_purchase.add_on.name,
          add_on_purchase: add_on_purchase.id,
          namespace: root_namespace.path
        )
      end
    end
  end
end
