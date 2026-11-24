# frozen_string_literal: true

module SeatAlert
  module Admin
    class ReachedComponent < BaseComponent
      private

      def title
        _('Your instance has reached its seat limit')
      end

      def body_text
        if restricted_access?
          safe_format(
            n_(
              'Your instance has used all %{total_seats} seat. Restricted ' \
                'access is blocking new users from being added to prevent overages. ' \
                'Purchase more seats or turn off restricted access to allow new users.',
              'Your instance has used all %{total_seats} seats. Restricted ' \
                'access is blocking new users from being added to prevent overages. ' \
                'Purchase more seats or turn off restricted access to allow new users.',
              total_user_count
            ),
            total_seats: total_user_count
          )
        else
          safe_format(
            n_(
              'Your instance has used all %{total_seats} seat. Adding new users ' \
                'will put your instance into overage. Purchase more seats or turn on ' \
                'restricted access to block new users automatically.',
              'Your instance has used all %{total_seats} seats. Adding new users ' \
                'will put your instance into overage. Purchase more seats or turn on ' \
                'restricted access to block new users automatically.',
              total_user_count
            ),
            total_seats: total_user_count
          )
        end
      end

      def alert_variant
        :warning
      end
    end
  end
end
