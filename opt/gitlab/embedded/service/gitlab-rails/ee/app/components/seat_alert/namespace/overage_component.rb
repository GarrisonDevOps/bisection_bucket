# frozen_string_literal: true

module SeatAlert
  module Namespace
    class OverageComponent < BaseComponent
      private

      def title
        _('Your namespace has exceeded its seat limit')
      end

      def body_text
        if restricted_access?
          safe_format(
            n_(
              'Your namespace has used %{used_seats} of %{total_seats} seat ' \
                '(%{overage_count} over limit). Restricted access is blocking new ' \
                'users from being added. Purchase more seats to resolve the overage.',
              'Your namespace has used %{used_seats} of %{total_seats} seats ' \
                '(%{overage_count} over limit). Restricted access is blocking new ' \
                'users from being added. Purchase more seats to resolve the overage.',
              total_seat_count
            ),
            used_seats: used_seats,
            total_seats: total_seat_count,
            overage_count: overage_count
          )
        else
          safe_format(
            n_(
              'Your namespace has used %{used_seats} of %{total_seats} seat ' \
                '(%{overage_count} over limit). Purchase more seats or turn on ' \
                'restricted access to prevent further overages.',
              'Your namespace has used %{used_seats} of %{total_seats} seats ' \
                '(%{overage_count} over limit). Purchase more seats or turn on ' \
                'restricted access to prevent further overages.',
              total_seat_count
            ),
            used_seats: used_seats,
            total_seats: total_seat_count,
            overage_count: overage_count
          )
        end
      end

      def overage_count
        remaining_seat_count.abs
      end

      def alert_variant
        :warning
      end

      def alert_class
        'js-overage-seat-count-threshold'
      end

      def alert_testid
        'overage-seat-count-threshold-alert'
      end

      def callout_feature_name
        Users::GroupCalloutsHelper::OVERAGE_SEAT_COUNT_THRESHOLD
      end
    end
  end
end
