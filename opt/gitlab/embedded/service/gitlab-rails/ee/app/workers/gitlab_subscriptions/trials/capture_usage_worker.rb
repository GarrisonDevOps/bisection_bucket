# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    class CaptureUsageWorker
      include ApplicationWorker

      data_consistency :sticky
      feature_category :acquisition
      urgency :low
      idempotent!
      deduplicate :until_executed
      concurrency_limit -> { 10 }
      defer_on_database_health_signal :gitlab_main_org, [:trial_usages], 1.minute

      def perform(gitlab_subscription_id)
        gitlab_subscription = GitlabSubscription.find_by_id(gitlab_subscription_id)
        return unless gitlab_subscription

        response = CaptureUsageService.new(gitlab_subscription).execute

        log_extra_metadata_on_done(:capture_status, response.status)
        log_extra_metadata_on_done(:capture_reason, response.reason) if response.error?
      end
    end
  end
end
