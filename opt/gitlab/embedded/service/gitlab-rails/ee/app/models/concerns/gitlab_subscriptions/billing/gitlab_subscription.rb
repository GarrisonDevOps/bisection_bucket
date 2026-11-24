# frozen_string_literal: true

module GitlabSubscriptions
  module Billing
    # The seats_in_use function matters for SOX compliance,
    # so we isolate the calculation in this module.
    # This lets us assign code owners to the related code.
    module GitlabSubscription
      extend ActiveSupport::Concern
      include Gitlab::Utils::StrongMemoize

      included do
        scope :requiring_seat_refresh, ->(limit) do
          # look for subscriptions that have not been refreshed in more than
          # 18 hours (catering for 6-hourly refresh schedule)
          with_a_paid_hosted_plan
            .where("last_seat_refresh_at < ? OR last_seat_refresh_at IS NULL", 18.hours.ago)
            .limit(limit)
        end
        scope :preload_for_refresh_seat, -> { preload(namespace: :route) }
      end

      # We need to show seats in use for free or trial subscriptions
      # in order to make it easy for customers to get this information.
      def seats_in_use
        return super if has_a_paid_hosted_plan?

        seats_in_use_now
      end

      def calculate_seats_in_use
        namespace.billable_members_count
      end

      # Refresh seat related attribute (without persisting them)
      def refresh_seat_attributes(reset_max: false)
        self.seats_in_use = calculate_seats_in_use
        self.max_seats_used = reset_max ? seats_in_use : [max_seats_used, seats_in_use].max
        self.seats_owed = calculate_seats_owed
      end

      private

      def seats_in_use_now
        calculate_seats_in_use
      end
      strong_memoize_attr :seats_in_use_now
    end
  end
end
