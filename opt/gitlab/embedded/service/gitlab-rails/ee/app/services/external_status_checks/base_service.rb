# frozen_string_literal: true

module ExternalStatusChecks
  class BaseService < BaseContainerService
    def external_status_check
      @external_status_check ||= container.external_status_checks.find(params[:id])
    end

    private

    def with_audit_logged(external_status_check, name, &block)
      audit_context = {
        name: name,
        author: current_user,
        scope: external_status_check.project,
        target: external_status_check
      }

      ::Gitlab::Audit::Auditor.audit(audit_context, &block)
    end
  end
end
