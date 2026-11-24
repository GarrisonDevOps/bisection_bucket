# frozen_string_literal: true

module ComplianceManagement
  class ComplianceFrameworkChangesAuditor < ::AuditEvents::BaseChangesAuditor
    def initialize(current_user, compliance_framework_setting, project)
      @project = project

      super(current_user, compliance_framework_setting)
    end

    def execute
      return if model.blank?

      if model.destroyed?
        audit_context = {
          author: @current_user,
          scope: @project,
          target: @project,
          message: 'Unassigned project compliance framework',
          name: 'compliance_framework_deleted'
        }
      else
        audit_context = {
          author: @current_user,
          scope: @project,
          target: model,
          message: "Assigned project compliance framework #{model.compliance_management_framework.name}",
          name: 'compliance_framework_id_updated'
        }
      end

      ::Gitlab::Audit::Auditor.audit(audit_context)
    end
  end
end
