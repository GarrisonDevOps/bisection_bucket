# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module ProjectSetting
      class AddFrameworkService < BaseFrameworkService
        include ::ComplianceManagement::Frameworks

        EVENT_TYPE = ::Projects::ComplianceFrameworkChangedEvent::EVENT_TYPES[:added].freeze

        def execute
          result = super
          return result if result.is_a?(ServiceResponse) && result.error?

          return project_framework_mismatch_error unless project_is_in_scope?
          return error unless framework.projects.push project

          enqueue_project_framework_evaluation
          publish_event(EVENT_TYPE)
          audit_event(EVENT_TYPE)

          success
        rescue ActiveRecord::RecordNotFound
          error
        rescue ActiveRecord::RecordNotUnique
          success
        end

        private

        def project_is_in_scope?
          project_framework_same_namespace?(project, framework)
        end

        def project_framework_mismatch_error
          ServiceResponse.error(
            message: format(_('Project %{project_name} and framework are not from same namespace.'),
              project_name: project.name
            )
          )
        end

        def error
          message = _("Project not found") unless project

          message ||= format(_("Failed to assign the framework to project %{project_name}"),
            project_name: project.name)

          ServiceResponse.error(message:)
        end

        def enqueue_project_framework_evaluation
          ComplianceManagement::ProjectComplianceEvaluatorWorker.schedule_compliance_evaluation(
            framework.id, [project.id]
          )
        end
      end
    end
  end
end
