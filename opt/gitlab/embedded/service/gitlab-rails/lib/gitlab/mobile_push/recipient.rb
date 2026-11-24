# frozen_string_literal: true

module Gitlab
  module MobilePush
    # A user as a push target: the checks every push asks before a send, the
    # registered phones and the working hours schedule. Expects the user's
    # preference and subscriptions to be preloaded.
    class Recipient
      attr_reader :user

      def initialize(user)
        @user = user
      end

      # Why no push may go to this user right now, or nil when one may.
      def skip_reason
        return :skipped_user_inactive unless user&.active?

        :skipped_no_subscription if subscriptions.empty?
      end

      def subscriptions
        @subscriptions ||= user.mobile_device_push_subscriptions.to_a
      end

      def working_hours_enabled?
        preference.mobile_push_working_hours_enabled?
      end

      def deliver_now?(now = Time.current)
        preference.mobile_push_deliver_now?(now)
      end

      def next_window_start(now = Time.current)
        preference.mobile_push_next_window_start(now)
      end

      private

      def preference
        user.user_preference
      end
    end
  end
end
