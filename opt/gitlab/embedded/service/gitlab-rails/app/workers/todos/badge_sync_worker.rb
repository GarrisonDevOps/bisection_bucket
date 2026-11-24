# frozen_string_literal: true

# rubocop:disable Sidekiq/EnforceDatabaseHealthSignalDeferral -- latency-sensitive, tiny DB load, see class comment
module Todos
  # Re-sends one user's pending to-do count to their registered devices as a
  # badge-only APNs notification. Enqueued by TodoService#enqueue_badge_sync
  # from every path that changes the count without creating a todo (resolve,
  # restore, snooze, target deletion): the alert pushes stamp the count on
  # the way up, and before this nothing moved the app badge on the way down.
  # Delivery lives in Notifications::MobilePush::SendBadgeUpdateService;
  # this worker only runs it and logs the returned tallies.
  #
  # One job per user, delayed by DELAY and deduplicated including the
  # scheduled set, so a bulk resolve (mark all done, a merge closing many
  # todos) collapses into a single push carrying the settled count; a change
  # that lands while a job is already running reschedules it once.
  #
  # Not deferred on database health signals for the same reason as
  # PushNotificationWorker: those indicators are instance-wide and would hold
  # a tiny, latency-sensitive job back for minutes.
  class BadgeSyncWorker
    include ApplicationWorker

    DELAY = 5.seconds

    data_consistency :delayed
    feature_category :notifications
    urgency :low
    worker_has_external_dependencies!
    idempotent!
    deduplicate :until_executed, if_deduplicated: :reschedule_once, including_scheduled: true

    def perform(user_id)
      response = ::Notifications::MobilePush::SendBadgeUpdateService.new(user_id).execute

      response.payload.each do |key, value|
        log_extra_metadata_on_done(key, value)
      end
    end
  end
end
# rubocop:enable Sidekiq/EnforceDatabaseHealthSignalDeferral
