# frozen_string_literal: true

module Notifications
  module MobilePush
    # Sends one summary push to each user whose working hours have just begun,
    # for the to-dos SendTodoNotificationsService held back while their pushes
    # were paused. WorkingHoursResumeWorker runs it every five minutes; the
    # payload tallies the outcomes each Gitlab::MobilePush::HeldSummary reports.
    class SendWorkingHoursSummariesService
      BATCH_SIZE = 1_000
      # Under the five-minute cron so two runs do not overlap. Users not reached
      # stay due for the next run.
      MAX_RUNTIME = 3.minutes

      def execute
        limiter = ::Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)
        outcomes = Hash.new(0)
        user_ids = ::Gitlab::MobilePush::WorkingHoursHold.due_user_ids(Time.current, limit: BATCH_SIZE)
        users = users_for(user_ids)

        # A deleted user would otherwise stay due forever and fill the batch.
        missing = user_ids - users.map(&:id)
        if missing.any?
          outcomes[:skipped_user_missing] = missing.count { |id| ::Gitlab::MobilePush::WorkingHoursHold.claim(id) }
        end

        users.each do |user|
          break if limiter.over_time?
          # Claimed right before its push, so a job killed mid-run loses one
          # summary at most, and two overlapping runs cannot both send.
          next unless ::Gitlab::MobilePush::WorkingHoursHold.claim(user.id)

          outcomes[::Gitlab::MobilePush::HeldSummary.new(user, sender: sender).resume] += 1
        end

        ServiceResponse.success(payload: outcomes)
      ensure
        @sender&.close
      end

      private

      # In due order, earliest first: Postgres returns an IN list in any order,
      # and a run the limiter cuts short should leave the newest holds behind.
      def users_for(user_ids)
        return [] if user_ids.empty?

        by_id = User.id_in(user_ids).preload_user_preference_and_push_subscriptions.index_by(&:id)
        user_ids.filter_map { |id| by_id[id] }
      end

      def sender
        @sender ||= ::Gitlab::MobilePush::Sender.new
      end
    end
  end
end
