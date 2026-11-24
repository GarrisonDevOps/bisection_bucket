# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module ComplianceRequirementsControls
      class DestroyService < BaseService
        attr_reader :current_user, :control

        def initialize(control:, current_user:)
          @control = control
          @current_user = current_user
        end

        def execute
          return ServiceResponse.error(message: _('Not permitted to destroy requirement control')) unless permitted?

          return error unless control.destroy

          refresh_requirement_statuses

          success
        end

        private

        def permitted?
          can? current_user, :admin_compliance_framework, control.compliance_requirement.framework
        end

        def success
          audit_destroy

          ServiceResponse.success(message: _('Compliance requirement control successfully deleted'))
        end

        def audit_destroy
          audit_context = {
            name: 'destroyed_compliance_requirement_control',
            author: current_user,
            scope: control.namespace,
            target: control,
            message: "Destroyed compliance requirement control #{control.name}"
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end

        def error
          ServiceResponse.error(message: _('Failed to destroy compliance requirement control'), payload: control.errors)
        end

        def refresh_requirement_statuses
          requirement_statuses = control.compliance_requirement.project_requirement_compliance_statuses

          requirement_statuses.each do |requirement_status|
            ComplianceManagement::ComplianceFramework::ComplianceRequirements::RefreshStatusService.new(
              requirement_status
            ).execute
          end
        end
      end
    end
  end
end
