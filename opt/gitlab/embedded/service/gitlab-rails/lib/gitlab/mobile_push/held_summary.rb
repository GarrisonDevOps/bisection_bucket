# frozen_string_literal: true

module Gitlab
  module MobilePush
    # One user taken off the working hours wake-up list, due for the generic
    # summary of the to-dos held while their pushes were paused. Re-asks every
    # check the per-todo path made hours ago, then sends or puts the user back
    # on the list, and answers with one outcome symbol for the caller to tally.
    class HeldSummary
      # ApnsClient folds a transport blip and a broken provider key into the same
      # :failed, so a failed summary retries within the window instead of waiting
      # a day; once the window closes, the next window start takes over.
      RETRY_DELAY = 15.minutes

      def initialize(user, sender:)
        @recipient = Recipient.new(user)
        @sender = sender
      end

      def resume
        skip_reason = recipient.skip_reason
        return skip_reason if skip_reason
        return :skipped_schedule_disabled unless recipient.working_hours_enabled?
        # Cleared on the web overnight: an alert with a badge of 0 points at nothing.
        return :skipped_nothing_pending if recipient.user.todos_pending_count == 0
        # A narrower window or a dropped weekday since the skip: wait for the
        # current schedule rather than land outside it.
        return reschedule unless recipient.deliver_now?

        deliver
      end

      private

      attr_reader :recipient, :sender

      def deliver
        payload = SummaryPayload.new(recipient.user)
        results = sender.deliver(recipient.subscriptions, delivered_as: 'working_hours_summary') { payload }
        return :delivered if results.include?(:delivered)
        # ApnsClient reports transport errors instead of raising, so without
        # this the summary would be lost. A dead token or missing APNs
        # credentials cannot recover, so they drop.
        return retry_later if results.include?(:failed)

        Sender::RESULT_LABELS.fetch(results.first, 'failed').to_sym
      end

      def reschedule(resume_at = recipient.next_window_start)
        return :dropped_no_window unless resume_at

        WorkingHoursHold.record(recipient.user.id, resume_at)
        :rescheduled
      end

      def retry_later
        retry_at = RETRY_DELAY.from_now
        return reschedule(retry_at) if recipient.deliver_now?(retry_at)

        reschedule
      end
    end
  end
end
