# frozen_string_literal: true

module Notifications
  module MobilePush
    # Pushes one user's pending to-do count to every registered device as a
    # badge-only notification (no alert, no sound): what
    # Todos::BadgeSyncWorker runs. Skips the same recipients as the alert
    # pushes (Gitlab::MobilePush::Recipient), evicts dead device tokens the
    # same way, and returns per-outcome tallies in the ServiceResponse
    # payload. Unlike the alert pushes there is no rate limit: a badge-only
    # push displays nothing, and the worker's deduplication bounds the rate
    # at one per user per delay window.
    class SendBadgeUpdateService
      def initialize(user_id)
        @user_id = user_id
      end

      def execute
        @results = Hash.new(0)
        @apns_results = Hash.new(0)

        subscriptions = deliverable_subscriptions(User.find_by_id(user_id))
        deliver(subscriptions) if subscriptions.any?

        ServiceResponse.success(payload: {
          subscription_count: subscriptions.size,
          results: @results,
          apns_results: @apns_results
        })
      ensure
        @sender&.close
      end

      private

      attr_reader :user_id

      def deliverable_subscriptions(user)
        recipient = ::Gitlab::MobilePush::Recipient.new(user)

        skip_reason = recipient.skip_reason
        return skip(skip_reason) if skip_reason

        recipient.subscriptions
      end

      def skip(outcome)
        record_outcome(outcome)
        []
      end

      # One payload for every device: its badge reads the count once.
      def deliver(subscriptions)
        payload = ::Gitlab::MobilePush::BadgePayload.new(subscriptions.first.user)

        results = sender.deliver(subscriptions) { payload }
        results.each { |result| @apns_results[result.to_s] += 1 }

        @results[results.include?(:delivered) ? 'delivered' : results.first.to_s] += 1
      end

      def sender
        @sender ||= ::Gitlab::MobilePush::Sender.new(counter)
      end

      def record_outcome(outcome)
        counter.increment(result: outcome.to_s)
        @results[outcome.to_s] += 1
      end

      def counter
        @counter ||= Gitlab::Metrics.counter(
          :mobile_push_badge_updates_total,
          'Count of mobile push badge update processing outcomes'
        )
      end
    end
  end
end
