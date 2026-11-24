# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    class ProjectsComplianceEnqueueWorker
      include ApplicationWorker

      version 1
      feature_category :compliance_management
      deduplicate :until_executed, including_scheduled: true
      data_consistency :sticky
      urgency :low
      idempotent!

      defer_on_database_health_signal :gitlab_main,
        [:compliance_management_frameworks, :project_compliance_framework_settings], 1.minute

      def perform(framework_id)
        return unless framework_id

        framework = ComplianceManagement::Framework.find_by_id(framework_id)

        return unless framework

        framework.projects.each_batch(of: 100) do |projects_batch|
          ComplianceManagement::ProjectComplianceEvaluatorWorker.schedule_compliance_evaluation(
            framework_id,
            projects_batch.pluck_primary_key
          )
        end
      end
    end
  end
end
