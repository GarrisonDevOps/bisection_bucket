# frozen_string_literal: true

module Admin
  module BlockSeatsOverages
    class NoSeatsLeftInSubscriptionAlertComponent < ViewComponent::Base
      def initialize(error)
        @error = error
      end

      attr_reader :error

      def render?
        return false unless ::Gitlab::CurrentSettings.seat_control_block_overages?

        !can_add_users?
      end

      private

      def can_add_users?
        error.to_s != EE::ApplicationSetting::ERROR_NO_SEATS_AVAILABLE
      end
    end
  end
end
