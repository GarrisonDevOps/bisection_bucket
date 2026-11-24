# frozen_string_literal: true

module SeatAlert
  module Admin
    class OverageComponent < BaseComponent
      private

      def title
        _('Your instance has exceeded its seat limit')
      end

      def body_text
        if restricted_access?
          safe_format(
            n_(
              'Your instance has used %{used_seats} of %{total_seats} seat ' \
                '(%{overage_count} over limit). Restricted access is blocking new ' \
                'users from being added. Purchase more seats to resolve the overage.',
              'Your instance has used %{used_seats} of %{total_seats} seats ' \
                '(%{overage_count} over limit). Restricted access is blocking new ' \
                'users from being added. Purchase more seats to resolve the overage.',
              total_user_count
            ),
            used_seats: used_seats,
            total_seats: total_user_count,
            overage_count: overage_count
          )
        else
          safe_format(
            n_(
              'Your instance has used %{used_seats} of %{total_seats} seat ' \
                '(%{overage_count} over limit). Purchase more seats or turn on ' \
                'restricted access to prevent further overages.',
              'Your instance has used %{used_seats} of %{total_seats} seats ' \
                '(%{overage_count} over limit). Purchase more seats or turn on ' \
                'restricted access to prevent further overages.',
              total_user_count
            ),
            used_seats: used_seats,
            total_seats: total_user_count,
            overage_count: overage_count
          )
        end
      end

      # Returns the number of seats over the limit.
      # This component is only rendered when remaining_user_count < 0 (overage state),
      # so negating it gives the positive overage count.
      def overage_count
        -remaining_user_count
      end

      def alert_variant
        :warning
      end
    end
  end
end
