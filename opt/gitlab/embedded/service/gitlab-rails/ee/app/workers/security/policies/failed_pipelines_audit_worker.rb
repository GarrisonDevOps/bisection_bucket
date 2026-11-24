# frozen_string_literal: true

module Security
  module Policies
    class FailedPipelinesAuditWorker
      include ApplicationWorker

      data_consistency :sticky

      feature_category :security_policy_management
      urgency :low
      idempotent!
      deduplicate :until_executed
      defer_on_database_health_signal :gitlab_main, [:project_audit_events], 1.minute

      # Audit stream to external destination with HTTP request if configured
      worker_has_external_dependencies!

      def perform(pipeline_id)
        pipeline = Ci::Pipeline.find_by_id(pipeline_id)
        return unless pipeline
        return unless ::Security::PolicyAvailability.available?(pipeline.project, :security_orchestration_policies)

        Security::SecurityOrchestrationPolicies::PipelineFailedAuditor.new(pipeline: pipeline).audit
      end
    end
  end
end
