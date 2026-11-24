# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    class ScheduleUsageCaptureWorker
      include ApplicationWorker
      include CronjobQueue

      data_consistency :sticky
      feature_category :acquisition
      idempotent!

      BATCH_SIZE = 100
      # Trial length is decided by CustomersDot (30 or 60 days), so "day 30" cannot be the trigger.
      # Every run inside the window refreshes the snapshot: the last day's numbers win and a failed
      # CustomersDot read gets a second try before trial credits stop being readable.
      CAPTURE_WINDOW_DAYS = 2

      def perform
        return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        return unless Feature.enabled?(:trial_usage_capture, :instance)

        scheduled_count = 0

        # One loop per day keeps every batch and boundary query on the (trial_ends_on, id) index.
        (1..CAPTURE_WINDOW_DAYS).each do |days_ahead|
          GitlabSubscription
            .with_ultimate_trial_ending_on(Date.current + days_ahead)
            .each_batch(of: BATCH_SIZE) do |batch|
              subscriptions = batch.preload_namespace_with_route.to_a

              CaptureUsageWorker.bulk_perform_async_with_contexts(
                subscriptions,
                arguments_proc: ->(subscription) { subscription.id },
                context_proc: ->(subscription) { { namespace: subscription.namespace } }
              )

              scheduled_count += subscriptions.size
            end
        end

        log_extra_metadata_on_done(:scheduled_count, scheduled_count)
      end
    end
  end
end
