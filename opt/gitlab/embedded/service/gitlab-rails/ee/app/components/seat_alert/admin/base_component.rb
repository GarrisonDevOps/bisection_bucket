# frozen_string_literal: true

module SeatAlert
  module Admin
    class BaseComponent < ViewComponent::Base
      include LicenseMonitoringHelper
      include SafeFormatHelper

      private

      def restricted_access?
        ::Gitlab::CurrentSettings.seat_control_block_overages?
      end

      def restricted_access_settings_path
        general_admin_application_settings_path(anchor: 'js-signup-settings')
      end

      def restricted_access_toggle_text
        restricted_access? ? _('Turn off restricted access') : _('Turn on restricted access')
      end

      def used_seats
        total_user_count - remaining_user_count
      end

      def purchase_link
        help_page_path('subscriptions/manage_seats.md', anchor: 'buy-more-seats')
      end

      def alert_options
        {
          class: 'gitlab-ee-license-banner js-admin-licensed-user-count-threshold',
          data: {
            feature_id: Users::CalloutsHelper::ACTIVE_USER_COUNT_THRESHOLD,
            dismiss_endpoint: callouts_path
          }
        }
      end

      def close_button_options
        { type: 'button', data: { testid: 'seat-alert-dismiss' } }
      end
    end
  end
end
