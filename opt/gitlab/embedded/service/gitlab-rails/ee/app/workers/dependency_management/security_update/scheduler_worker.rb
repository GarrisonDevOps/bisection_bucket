# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    class SchedulerWorker
      include Gitlab::EventStore::Subscriber

      data_consistency :delayed
      feature_category :dependency_management
      urgency :low
      deduplicate :until_executed
      idempotent!

      MAX_SCHEDULER_WORKER_LIMIT = 200

      concurrency_limit -> do
        [Gitlab::CurrentSettings.security_update_scheduler_max_concurrency, MAX_SCHEDULER_WORKER_LIMIT].min
      end

      defer_on_database_health_signal :gitlab_sec, [:sbom_occurrences], 1.minute

      def handle_event(event)
        pipeline_id = event.data['pipeline_id']

        return unless pipeline_id.present?

        pipeline = Ci::Pipeline.find_by(id: pipeline_id) # rubocop:disable CodeReuse/ActiveRecord -- Single lookup; no finder abstraction needed for one-time pipeline fetch

        return unless pipeline&.project
        return unless DependencyManagement::SecurityUpdate::Eligibility.trigger_pipeline?(pipeline)

        DependencyManagement::SecurityUpdate::SchedulerService.execute(project: pipeline.project)
      end
    end
  end
end
