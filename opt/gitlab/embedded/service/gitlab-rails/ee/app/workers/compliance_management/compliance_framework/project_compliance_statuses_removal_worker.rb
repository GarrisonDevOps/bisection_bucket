# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    class ProjectComplianceStatusesRemovalWorker
      include ApplicationWorker

      version 1
      feature_category :compliance_management
      deduplicate :until_executed, including_scheduled: true
      data_consistency :sticky
      urgency :low
      idempotent!

      def perform(project_id, framework_id, params = {})
        return unless project_id && framework_id

        # In case the framework was reapplied to the project till the time this job started,
        # don't delete any of the compliance statuses
        return if !params["skip_framework_check"] &&
          ComplianceManagement::ComplianceFramework::ProjectSettings.by_framework_and_project(project_id,
            framework_id).exists?

        ComplianceManagement::ComplianceFramework::ProjectRequirementStatuses::BulkDestroyService.new(project_id,
          framework_id).execute

        ComplianceManagement::ComplianceFramework::ProjectControlStatuses::BulkDestroyService.new(project_id,
          framework_id).execute
      end
    end
  end
end
