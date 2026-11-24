# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class ProcessPipelineCompletionWorker
      include Gitlab::EventStore::Subscriber
      include ::Security::ScanResultPolicies::PolicyLogger

      feature_category :security_policy_management
      data_consistency :sticky
      idempotent!
      deduplicate :until_executing, including_scheduled: true

      def handle_event(event)
        pipeline = Ci::Pipeline.find_by_id_and_partition(event.data[:pipeline_id], event.data[:partition_id])
        return unless pipeline

        project = pipeline.project

        return unless ::Security::PolicyAvailability.available?(project, :security_orchestration_policies)
        return unless project.can_store_security_reports?

        # When triggered by PipelineFinishedEvent, skip if security scans are still
        # being ingested. ReportsIngestedEvent will trigger the evaluation after
        # ingestion completes with findings guaranteed to be present.
        if event.is_a?(::Ci::PipelineFinishedEvent) && !::Security::Scan.results_ready?(pipeline)
          return log_deferred_evaluation(pipeline, 'scans_stored')
        end

        if event.is_a?(::Ci::PipelineFinishedEvent) && ::Security::Scan.ingestion_pending?(pipeline)
          return log_deferred_evaluation(pipeline, 'ingestion')
        end

        # Inline, so the evaluation is not parked behind the worker's concurrency limit, which
        # exists for policy-sync fan-out, while the unblock timeout is running.
        ::Security::ScanResultPolicies::SyncFindingsToApprovalRulesService.new(pipeline).execute
      end

      private

      def log_deferred_evaluation(pipeline, waiting_for)
        log_policy_evaluation('pipeline_completion', 'Deferring policy evaluation until security reports are ready',
          Labkit::Fields::GL_PROJECT_PATH => pipeline.project.full_path, Labkit::Fields::GL_PIPELINE_ID => pipeline.id,
          decision: 'deferred', waiting_for: waiting_for)
      end
    end
  end
end
