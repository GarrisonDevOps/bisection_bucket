# frozen_string_literal: true

module Notifications
  module MobilePush
    # Every five minutes: users whose working hours have just begun get one
    # summary push for the to-dos skipped while their pushes were paused
    # (SendTodoNotificationsService#hold_for_working_hours). Delivery lives in
    # SendWorkingHoursSummariesService; this worker runs it and logs the tally.
    # It honors the instance-wide mobile_push_notifications_dispatch flag, and
    # the built-in per-worker drop flag can also stop it.
    class WorkingHoursResumeWorker
      include ApplicationWorker
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- instance-wide sweep, no meaningful context

      idempotent!
      data_consistency :sticky
      feature_category :notifications
      urgency :low
      worker_has_external_dependencies!
      defer_on_database_health_signal :gitlab_main, [:mobile_device_push_subscriptions], 5.minutes

      def perform
        # The instance-wide kill switch must stop the summaries too, not only the
        # per-todo pushes. Held users wait in Redis and are told once pushes resume.
        return unless Feature.enabled?(:mobile_push_notifications_dispatch) # rubocop:disable Gitlab/FeatureFlagWithoutActor -- instance-wide dispatch gate, as in TodoService

        response = ::Notifications::MobilePush::SendWorkingHoursSummariesService.new.execute

        response.payload.each do |outcome, count|
          log_extra_metadata_on_done(outcome, count)
        end
      end
    end
  end
end
