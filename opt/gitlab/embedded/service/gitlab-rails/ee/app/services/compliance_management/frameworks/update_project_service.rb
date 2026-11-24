# frozen_string_literal: true

module ComplianceManagement
  module Frameworks
    class UpdateProjectService < BaseService
      def initialize(project, current_user, frameworks)
        @project = project
        @current_user = current_user
        @frameworks = frameworks
      end

      def execute
        return error unless permitted?

        old_frameworks = project.compliance_management_frameworks

        frameworks_to_be_added = frameworks - old_frameworks
        frameworks_to_be_removed = old_frameworks - frameworks

        frameworks_to_be_added.each do |framework|
          response = add_framework_setting(framework)
          return response if response.respond_to?(:error?) && response.error?
        end

        frameworks_to_be_removed.each do |framework|
          response = remove_framework_setting(framework)
          return response if response.respond_to?(:error?) && response.error?
        end

        success
      end

      private

      attr_reader :project, :current_user, :frameworks

      def add_framework_setting(framework)
        return unless project_is_in_root_or_csp_namespace(framework)

        framework_project_setting = ComplianceManagement::ComplianceFramework::ProjectSettings.new(project: project,
          compliance_management_framework: framework)

        unless framework_project_setting.save
          error_message = "Error while adding framework #{framework.name}. Errors: " \
            "#{framework_project_setting.errors.full_messages.to_sentence}"

          return error(error_message)
        end

        ComplianceManagement::ProjectComplianceEvaluatorWorker.schedule_compliance_evaluation(
          framework.id, [project.id]
        )

        track_event(::Projects::ComplianceFrameworkChangedEvent::EVENT_TYPES[:added], framework)
      end

      def project_is_in_root_or_csp_namespace(framework)
        project.root_namespace.self_and_descendants_ids.include?(framework.namespace_id) ||
          (project.csp_namespace && project.csp_namespace.self_and_descendants_ids.include?(framework.namespace_id))
      end

      def remove_framework_setting(framework)
        framework_project_setting = ComplianceManagement::ComplianceFramework::ProjectSettings
                                      .by_framework_and_project(project.id, framework.id).first

        unless framework_project_setting.destroy
          error_message = "Error while removing framework #{framework.name}. Errors: " \
            "#{framework_project_setting.errors.full_messages.to_sentence}"
          return error(error_message)
        end

        enqueue_project_compliance_status_removal(framework)

        track_event(::Projects::ComplianceFrameworkChangedEvent::EVENT_TYPES[:removed], framework)
      end

      def enqueue_project_compliance_status_removal(framework)
        ComplianceManagement::ComplianceFramework::ProjectComplianceStatusesRemovalWorker.perform_in(
          ComplianceManagement::ComplianceFramework::ProjectSettings::PROJECT_EVALUATOR_WORKER_DELAY,
          project.id, framework.id
        )
      end

      def permitted?
        can?(current_user, :admin_compliance_framework, project)
      end

      def error(message = _("Failed to assign the framework to the project"))
        ServiceResponse.error(message: message)
      end

      def success
        ServiceResponse.success
      end

      def track_event(event_type, framework)
        publish_event(event_type, framework)
        audit_event(event_type, framework)
      end

      def audit_event(event_type, framework)
        audit_context = {
          name: "compliance_framework_#{event_type}",
          author: current_user,
          scope: project,
          target: framework,
          message: %(#{event_type.capitalize} 'framework label': "#{framework.name}"),
          additional_details: {
            framework: {
              id: framework.id,
              name: framework.name
            }
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def publish_event(event_type, framework)
        event = ::Projects::ComplianceFrameworkChangedEvent.new(data: {
          project_id: project.id,
          compliance_framework_id: framework.id,
          event_type: event_type
        })

        ::Gitlab::EventStore.publish(event)
      end
    end
  end
end
