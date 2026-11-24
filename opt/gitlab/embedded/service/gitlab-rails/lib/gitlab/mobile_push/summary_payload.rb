# frozen_string_literal: true

module Gitlab
  module MobilePush
    # Generic per-user alert: sent once when the per-user push rate limit is
    # first exceeded within a window, and once when a user's working hours
    # begin (HeldSummary). Carries no todo content; the badge and this fixed
    # sentence are all the device receives.
    class SummaryPayload
      BODY = 'You have new to-dos'

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
        BODY
      end

      def badge
        user.todos_pending_count
      end

      def thread_id
        nil
      end

      def collapse_id
        "summary-#{user.id}"
      end

      def mutable_content?
        false
      end

      def gitlab_data
        { version: 1, type: 'summary', user_id: user.id }
      end

      private

      attr_reader :user
    end
  end
end
