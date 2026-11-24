# frozen_string_literal: true

module Security
  module Policies
    class ReportSecurityPoliciesMetricsWorker
      include ApplicationWorker
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- This worker does not perform work scoped to a context

      idempotent!
      feature_category :security_policy_management
      data_consistency :sticky
      urgency :low

      def perform
        build_count = ::Ci::Build.with_pipeline_source_type('security_orchestration_policy')
                   .with_status(*::Ci::HasStatus::ALIVE_STATUSES)
                   .created_after(1.hour.ago)
                   .updated_after(1.hour.ago)
                   .count

        limit_metric = Gitlab::Metrics.gauge(:security_policies_active_builds_scheduled_scans,
          'Number of active ci builds created by scan execution policy scheduled scans.',
          {})
        limit_metric.set({}, build_count)
        # rubocop:disable Database/RescueQueryCanceled -- When a timeout occurs, the metric is not updated.
        # For now, we are gracefully rescuing and logging this error, since the worker runs every minute, and the
        # metric should be updated soon enough.
        # We will monitor and evaluate if a query update is required
      rescue ActiveRecord::QueryCanceled => e
        Gitlab::ErrorTracking.log_exception(e, metric: 'security_policies_active_builds_scheduled_scans')
      end
      # rubocop:enable Database/RescueQueryCanceled
    end
  end
end
