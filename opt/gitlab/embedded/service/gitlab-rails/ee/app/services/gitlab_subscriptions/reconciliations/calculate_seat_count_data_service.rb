# frozen_string_literal: true

module GitlabSubscriptions
  module Reconciliations
    class CalculateSeatCountDataService
      attr_reader :namespace, :subscription, :user

      delegate :max_seats_used, :max_seats_used_changed_at, :seats, :seats_remaining, to: :subscription

      def initialize(namespace:, subscription:, user:)
        @namespace = namespace
        @subscription = subscription
        @user = user
      end

      def execute
        return unless subscription.present?
        return if max_seats_used_changed_at.nil? || user_dismissed_alert?
        return unless seat_count_threshold_reached?
        return unless alert_user_overage?

        {
          namespace: namespace,
          remaining_seat_count: seats_remaining,
          seats_in_use: max_seats_used,
          total_seat_count: seats
        }
      end

      private

      def alert_user_overage?
        CheckSeatUsageAlertsEligibilityService.new(namespace: namespace).execute
      end

      def seat_count_threshold_reached?
        return false unless max_seats_used
        return false if max_seats_used >= seats

        ::GitlabSubscriptions::SeatThresholds.threshold_reached?(
          seats_total: seats,
          seats_used: max_seats_used
        )
      end

      def user_dismissed_alert?
        user.dismissed_callout_for_group?(
          feature_name: Users::GroupCalloutsHelper::APPROACHING_SEAT_COUNT_THRESHOLD,
          group: namespace,
          ignore_dismissal_earlier_than: max_seats_used_changed_at
        )
      end
    end
  end
end
