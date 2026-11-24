# frozen_string_literal: true

module Analytics
  module Orbit
    class DisableBetaEnrollmentsWorker
      include ApplicationWorker
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- instance-wide cron job, no single group or user context

      data_consistency :sticky
      feature_category :knowledge_graph
      urgency :low
      worker_has_external_dependencies!
      deduplicate :until_executed
      idempotent!
      defer_on_database_health_signal :gitlab_main_org,
        [:orbit_namespace_enrollments, :knowledge_graph_enabled_namespaces], 10.minutes

      def perform
        return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        # Only a fully enabled flag starts the cleanup, not an actor or percentage rollout.
        return unless ::Feature.enabled?(:orbit_promo_access_gate) # rubocop:disable Gitlab/FeatureFlagWithoutActor -- instance-wide cleanup

        result = DisableBetaEnrollmentsService.new.execute
        log_extra_metadata_on_done(:disabled_count, result.payload[:disabled_count])
        log_extra_metadata_on_done(:converted_count, result.payload[:converted_count])
        log_extra_metadata_on_done(:over_time, result.payload[:over_time])
      end
    end
  end
end
