# frozen_string_literal: true

module SeatAlert
  module Namespace
    class BaseComponent < ViewComponent::Base
      include SafeFormatHelper

      def initialize(root_namespace:, current_user:, remaining_seat_count:, total_seat_count:)
        @root_namespace = root_namespace
        @current_user = current_user
        @remaining_seat_count = remaining_seat_count
        @total_seat_count = total_seat_count
      end

      private

      attr_reader :root_namespace, :current_user, :remaining_seat_count, :total_seat_count

      def restricted_access?
        root_namespace.block_seat_overages?
      end

      def restricted_access_settings_path
        helpers.edit_group_path(root_namespace, anchor: 'js-permissions-settings')
      end

      def restricted_access_toggle_text
        restricted_access? ? _('Turn off restricted access') : _('Turn on restricted access')
      end

      def used_seats
        total_seat_count - remaining_seat_count
      end

      def purchase_link
        helpers.help_page_path('subscriptions/manage_seats.md', anchor: 'buy-more-seats')
      end

      def alert_options
        {
          class: alert_class,
          data: {
            testid: alert_testid,
            feature_id: callout_feature_name,
            dismiss_endpoint: helpers.group_callouts_path,
            group_id: root_namespace.id
          }
        }
      end

      def close_button_options
        { data: { testid: "#{alert_testid}-dismiss" } }
      end

      def alert_testid
        raise NotImplementedError, "Subclasses must implement alert_testid"
      end

      def callout_feature_name
        raise NotImplementedError, "Subclasses must implement callout_feature_name"
      end
    end
  end
end
