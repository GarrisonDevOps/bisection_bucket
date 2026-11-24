# frozen_string_literal: true

module EE
  module Members
    module RequestAccessService
      extend ::Gitlab::Utils::Override
      include ::GitlabSubscriptions::MemberManagement::PromotionManagementUtils

      private

      override :can_request_access?
      def can_request_access?(source)
        super && !membership_locked?(source)
      end

      override :default_access_level
      def default_access_level
        if member_promotion_management_enabled? && non_billable_user?(current_user)
          ::Gitlab::Access::GUEST
        else
          super
        end
      end

      def non_billable_user?(user)
        ::User.non_billable_users_for_billable_management([user.id]).present?
      end
    end
  end
end
