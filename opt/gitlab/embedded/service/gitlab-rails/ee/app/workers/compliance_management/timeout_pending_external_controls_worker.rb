# frozen_string_literal: true

module ComplianceManagement
  class TimeoutPendingExternalControlsWorker
    include ApplicationWorker

    idempotent!
    feature_category :compliance_management
    data_consistency :sticky
    urgency :low

    PENDING_STATUS_TIMEOUT = 30.minutes

    def perform(args = {})
      @args = args.with_indifferent_access

      return unless valid_control?
      return unless valid_project_control_compliance_status?
      return unless timeout_project_control_compliance_status?

      @project_control_compliance_status.fail!

      create_audit_log
    end

    private

    def valid_control?
      control_id = @args[:control_id]
      @control = ComplianceManagement::ComplianceFramework::ComplianceRequirementsControl.find_by_id(control_id)
      @control.present?
    end

    def valid_project_control_compliance_status?
      control_id, project_id = @args.values_at(:control_id, :project_id)
      @project_control_compliance_status = ComplianceManagement::ComplianceFramework::ProjectControlComplianceStatus
                                             .for_project_and_control(project_id, control_id).last

      @project_control_compliance_status.present?
    end

    def timeout_project_control_compliance_status?
      @project_control_compliance_status.pending? &&
        @project_control_compliance_status.updated_at < PENDING_STATUS_TIMEOUT.ago
    end

    def create_audit_log
      audit_context = {
        name: 'pending_compliance_external_control_failed',
        author: ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
        scope: @project_control_compliance_status.project,
        target: @project_control_compliance_status.project,
        message: "Project control compliance status with URL #{@control.external_url} marked as fail."
      }

      ::Gitlab::Audit::Auditor.audit(audit_context)
    end
  end
end
