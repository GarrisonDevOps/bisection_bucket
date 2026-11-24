# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    class CreateUserAddOnAssignmentWorker
      include ApplicationWorker
      include GitlabSubscriptions::AddOnPurchases::UserAddOnAssignmentCommon

      data_consistency :sticky
      feature_category :subscription_management
      idempotent!

      def perform(user_id, root_namespace_id = nil)
        @root_namespace_id = root_namespace_id
        @user_id = user_id

        return unless user && add_on_purchase&.active? && valid_params?

        create_class.new(
          add_on_purchase: add_on_purchase,
          user: user
        ).execute
      end

      private

      def valid_params?
        valid_for_self_managed? || valid_for_saas?
      end

      def valid_for_self_managed?
        root_namespace_id.nil?
      end

      def valid_for_saas?
        root_namespace_id.present? && ::Gitlab::Saas.feature_available?(:gitlab_duo_saas_only)
      end

      def create_class
        return GitlabSubscriptions::UserAddOnAssignments::Saas::CreateService if root_namespace_id.present?

        GitlabSubscriptions::UserAddOnAssignments::SelfManaged::CreateService
      end
    end
  end
end
