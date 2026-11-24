# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module ComplianceRequirementsControls
      class UpdateStatusService < BaseService
        include Gitlab::Utils::StrongMemoize
        include Gitlab::InternalEventsTracking

        VALID_STATUSES = %w[pass fail not_applicable].freeze

        def initialize(current_user:, control:, project:, status_value:, params: {})
          @current_user = current_user
          @control = control
          @project = project
          @status_value = status_value
          @params = params
        end

        def execute
          return error('Not permitted to update compliance control status') unless permitted?
          return error("'#{status_value}' is not a valid status") unless valid_status?

          return error(control_status.errors.full_messages.join(', ')) unless update_control_status

          audit_changes
          refresh_requirement_status
          success
        end

        private

        attr_reader :control, :project, :status_value

        def audit_changes
          old_status = control_status.status_before_last_save
          new_status = control_status.status

          return if old_status == new_status

          audit_context = {
            name: "compliance_control_status_#{new_status}",
            scope: project,
            target: control_status,
            message: "Changed compliance control status from '#{old_status}' to '#{new_status}'",
            author: current_user
          }
          ::Gitlab::Audit::Auditor.audit(audit_context)
          track_changes(old_status, new_status)
        end

        def track_changes(old_status, new_status)
          event_name = ''

          event_name = 'g_sscs_compliance_control_status_pass_to_fail' if old_status == 'pass' && new_status == 'fail'
          event_name = 'g_sscs_compliance_control_status_fail_to_pass' if old_status == 'fail' && new_status == 'pass'

          return if event_name.empty?

          event_args = {
            namespace: project.namespace,
            project: project,
            additional_properties: {
              property: control.control_type.to_s
            }
          }

          event_args[:user] = current_user if current_user.is_a?(::User)

          track_internal_event(event_name, event_args)
        end

        def permitted?
          project.licensed_feature_available?(:custom_compliance_frameworks)
        end

        def update_control_status
          control_status.update(status: status_value)
        end

        def success
          ServiceResponse.success(payload: { status: control_status.status })
        end

        def valid_status?
          status_value.in?(VALID_STATUSES)
        end

        def control_status
          ComplianceManagement::ComplianceFramework::ProjectControlComplianceStatus
            .create_or_find_for_project_and_control(project, control)
        end
        strong_memoize_attr :control_status

        def error(error_message)
          ServiceResponse.error(
            message: format(
              _("Failed to update compliance control status. Error: %{error_message}"),
              error_message: error_message
            )
          )
        end

        def refresh_requirement_status
          return unless params[:refresh_requirement_status]

          requirement_status = ComplianceManagement::ComplianceFramework::ProjectRequirementComplianceStatus
            .find_or_create_project_and_requirement(project, control.compliance_requirement)

          ComplianceManagement::ComplianceFramework::ComplianceRequirements::RefreshStatusService
            .new(requirement_status)
            .execute
        end
      end
    end
  end
end
