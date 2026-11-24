# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module ProjectSetting
      class RemoveFrameworkService < BaseFrameworkService
        EVENT_TYPE = ::Projects::ComplianceFrameworkChangedEvent::EVENT_TYPES[:removed].freeze

        def execute
          result = super

          return result if result.is_a?(ServiceResponse) && result.error?

          return error unless framework.projects.destroy(project.id)

          enqueue_project_compliance_status_removal
          publish_event(EVENT_TYPE)
          audit_event(EVENT_TYPE)

          success
        rescue ActiveRecord::RecordNotFound
          success
        end

        private

        def error
          ServiceResponse.error(message: format(_("Failed to remove the framework from project %{project_name}"),
            project_name: project.name))
        end

        def enqueue_project_compliance_status_removal
          ComplianceManagement::ComplianceFramework::ProjectComplianceStatusesRemovalWorker.perform_in(
            ComplianceManagement::ComplianceFramework::ProjectSettings::PROJECT_EVALUATOR_WORKER_DELAY,
            project.id, framework.id
          )
        end
      end
    end
  end
end
