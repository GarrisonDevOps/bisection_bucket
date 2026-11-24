# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    class DestroyUserAddOnAssignmentWorker
      include ::ApplicationWorker
      include GitlabSubscriptions::AddOnPurchases::UserAddOnAssignmentCommon

      data_consistency :sticky
      feature_category :subscription_management
      idempotent!

      def perform(user_id, root_namespace_id = nil)
        @root_namespace_id = root_namespace_id
        @user_id = user_id

        return unless [user, add_on_purchase, assignment].all?(&:present?)

        GitlabSubscriptions::Duo::BulkUnassignService.new(
          add_on_purchase: add_on_purchase,
          user_ids: [user.id]
        ).execute
      end
    end
  end
end
