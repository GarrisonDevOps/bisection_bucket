# frozen_string_literal: true

module Gitlab
  module MobilePush
    # Badge-only notification: no alert text, no sound, just the user's
    # pending to-do count for the app icon. Sent by
    # Notifications::MobilePush::SendBadgeUpdateService when the count
    # changed without a new todo (resolve, restore, snooze, deletion), so a
    # device that heard the count go up through the alert pushes also hears
    # it go down. iOS applies the number without waking the app or its
    # notification service extension, so the app needs no handling for it.
    class BadgePayload
      def initialize(user)
        @user = user
      end

      def title
        nil
      end

      def subtitle
        nil
      end

      def body
        nil
      end

      # Forced rather than cached: snoozing changes the pending count (the
      # pending scope is `not_snoozed`) but refreshes no cache, so the cached
      # number may be the stale one this push exists to correct. Memoized so
      # a user's several devices cost one count.
      def badge
        @badge ||= user.todos_pending_count(force: true)
      end

      def thread_id
        nil
      end

      def collapse_id
        "badge-#{user.id}"
      end

      def mutable_content?
        false
      end

      def gitlab_data
        { version: 1, type: 'badge', user_id: user.id }
      end

      private

      attr_reader :user
    end
  end
end
