# frozen_string_literal: true

module SeatAlert
  module Namespace
    class ThresholdComponent < BaseComponent
      private

      def title
        _('Your namespace is approaching its seat limit')
      end

      def body_text
        if restricted_access?
          safe_format(
            _('Your namespace has used %{used_seats} of %{total_seats} seats. ' \
              'When no seats remain, restricted access will block new users from ' \
              'being added to prevent overages.'),
            used_seats: used_seats,
            total_seats: total_seat_count
          )
        else
          safe_format(
            _('Your namespace has used %{used_seats} of %{total_seats} seats. ' \
              'When no seats remain, adding new users will put your namespace into ' \
              'overage. Purchase more seats or turn on restricted access to block ' \
              'new users automatically.'),
            used_seats: used_seats,
            total_seats: total_seat_count
          )
        end
      end

      def alert_variant
        :info
      end

      def alert_class
        'js-approaching-seat-count-threshold'
      end

      def alert_testid
        'approaching-seat-count-threshold-alert'
      end

      def callout_feature_name
        Users::GroupCalloutsHelper::APPROACHING_SEAT_COUNT_THRESHOLD
      end
    end
  end
end
