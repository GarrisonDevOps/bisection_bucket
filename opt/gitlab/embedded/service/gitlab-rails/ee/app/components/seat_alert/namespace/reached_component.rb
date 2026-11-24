# frozen_string_literal: true

module SeatAlert
  module Namespace
    class ReachedComponent < BaseComponent
      private

      def title
        _('Your namespace has reached its seat limit')
      end

      def body_text
        if restricted_access?
          safe_format(
            n_(
              'Your namespace has used all %{total_seats} seat. Restricted ' \
                'access is blocking new users from being added to prevent overages. ' \
                'Purchase more seats or turn off restricted access to allow new users.',
              'Your namespace has used all %{total_seats} seats. Restricted ' \
                'access is blocking new users from being added to prevent overages. ' \
                'Purchase more seats or turn off restricted access to allow new users.',
              total_seat_count
            ),
            total_seats: total_seat_count
          )
        else
          safe_format(
            n_(
              'Your namespace has used all %{total_seats} seat. Adding new users ' \
                'will put your namespace into overage. Purchase more seats or turn on ' \
                'restricted access to block new users automatically.',
              'Your namespace has used all %{total_seats} seats. Adding new users ' \
                'will put your namespace into overage. Purchase more seats or turn on ' \
                'restricted access to block new users automatically.',
              total_seat_count
            ),
            total_seats: total_seat_count
          )
        end
      end

      def alert_variant
        :warning
      end

      def alert_class
        'js-reached-seat-count-threshold'
      end

      def alert_testid
        'reached-seat-count-threshold-alert'
      end

      def callout_feature_name
        Users::GroupCalloutsHelper::REACHED_SEAT_COUNT_THRESHOLD
      end
    end
  end
end
