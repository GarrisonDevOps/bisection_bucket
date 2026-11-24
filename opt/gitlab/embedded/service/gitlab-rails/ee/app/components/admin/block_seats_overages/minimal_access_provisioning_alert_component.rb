# frozen_string_literal: true

module Admin
  module BlockSeatsOverages
    class MinimalAccessProvisioningAlertComponent < ViewComponent::Base
      def initialize(current_user:)
        @current_user = current_user
      end

      def render?
        return false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        return false unless @current_user&.can_admin_all_resources?
        return false unless ::Gitlab::CurrentSettings.seat_control_block_overages?

        current_count = affected_users_count
        return false unless current_count > 0

        current_count > count_at_last_dismissal
      end

      private

      def affected_users_count
        ::GitlabSubscriptions::MemberManagement::SeatAwareProvisioning
          .instance_affected_users_count
      end

      def count_at_last_dismissal
        ::GitlabSubscriptions::MemberManagement::SeatAwareProvisioning
          .instance_count_at_last_dismissal(@current_user)
      end

      def purchase_seats_link
        subscription_portal_manage_url
      end

      def learn_more_link
        help_page_url('subscriptions/manage_seats.md', anchor: 'buy-more-seats')
      end

      def restricted_access_link
        help_page_url('subscriptions/manage_seats.md', anchor: 'restricted-access')
      end

      def dismiss_path
        admin_minimal_access_provisioning_alert_dismissal_path
      end
    end
  end
end
