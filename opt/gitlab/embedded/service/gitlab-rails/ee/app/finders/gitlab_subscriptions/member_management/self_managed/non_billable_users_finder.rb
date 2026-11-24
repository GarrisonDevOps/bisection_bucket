# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    module SelfManaged
      class NonBillableUsersFinder
        include GitlabSubscriptions::MemberManagement::PromotionManagementUtils

        def initialize(current_user, user_ids)
          @current_user = current_user
          @user_ids = user_ids
        end

        def execute
          return User.none unless current_user.present? && user_ids.present? && member_promotion_management_enabled?

          User.non_billable_users_for_billable_management(user_ids)
        end

        private

        attr_reader :current_user, :user_ids
      end
    end
  end
end
