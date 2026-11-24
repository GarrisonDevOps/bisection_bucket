# frozen_string_literal: true

module Namespaces
  module BlockSeatOverages
    class MinimalAccessProvisioningAlertComponent < ViewComponent::Base
      def initialize(current_user:, root_namespace:)
        @current_user = current_user
        @root_namespace = root_namespace
      end

      def render?
        return false unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        return false unless Ability.allowed?(current_user, :edit_billing, root_namespace)
        return false unless root_namespace.block_seat_overages?

        current_count = affected_users_count
        return false unless current_count > 0

        current_count > count_at_last_dismissal
      end

      private

      attr_reader :current_user, :root_namespace

      def affected_users_count
        ::GitlabSubscriptions::MemberManagement::SeatAwareProvisioning
          .group_affected_users_count(root_namespace)
      end

      def count_at_last_dismissal
        ::GitlabSubscriptions::MemberManagement::SeatAwareProvisioning
          .group_count_at_last_dismissal(root_namespace, current_user)
      end

      def purchase_seats_link
        ::Gitlab::Routing.url_helpers.subscription_portal_add_extra_seats_url(root_namespace.id)
      end

      def learn_more_link
        help_page_url('subscriptions/manage_seats.md', anchor: 'buy-more-seats')
      end

      def restricted_access_link
        help_page_url('subscriptions/manage_seats.md', anchor: 'restricted-access')
      end

      def dismiss_path
        group_minimal_access_provisioning_alert_dismissal_path(root_namespace)
      end
    end
  end
end
