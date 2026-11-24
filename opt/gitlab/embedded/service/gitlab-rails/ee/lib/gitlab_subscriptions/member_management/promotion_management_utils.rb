# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    module PromotionManagementUtils
      include ::GitlabSubscriptions::SubscriptionHelper
      include ::GitlabSubscriptions::BillableUsersUtils

      def member_promotion_management_enabled?
        return false unless promotion_management_settings_enabled?

        member_promotion_management_feature_available?
      end

      def member_promotion_management_feature_available?
        return false if gitlab_com_subscription?

        exclude_guests?
      end

      def promotion_management_required_for_role?(new_access_level:, member_role_id: nil)
        return false unless member_promotion_management_enabled?

        sm_billable_role_change?(role: new_access_level, member_role_id: member_role_id)
      end

      def trigger_event_to_promote_pending_members!(member)
        return unless member_promotion_management_enabled?
        return unless member_eligible_for_admin_event?(member)

        return unless ::GitlabSubscriptions::MemberManagement::MemberApproval
                        .pending_member_approvals_for_user(member.user_id)
                        .exists?

        ::Gitlab::EventStore.publish(
          ::Members::MembershipModifiedByAdminEvent.new(data: {
            member_user_id: member.user_id
          })
        )
      end

      private

      def member_eligible_for_admin_event?(member)
        return false unless member.present?
        return false unless member.persisted?
        return false unless member.errors.empty?
        return false unless member.user_id.present?

        promotion_management_required_for_role?(
          new_access_level: member.access_level,
          member_role_id: member.member_role_id
        )
      end

      def promotion_management_settings_enabled?
        ::Gitlab::CurrentSettings.enable_member_promotion_management?
      end

      def exclude_guests?
        License.current&.exclude_guests_from_active_count?
      end
    end
  end
end
