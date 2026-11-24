# frozen_string_literal: true

module Security
  module Configuration
    class SetProjectValidityChecksService < SetProjectSecuritySettingBaseService
      private

      def setting_key
        :validity_checks_enabled
      end

      def subject_project_ids
        [@subject.id] - @excluded_projects_ids
      end

      def audit
        message = "Validity checks has been #{@enable ? 'enabled' : 'disabled'}"
        audit_context = build_audit_context(
          name: 'project_security_setting_updated',
          message: message
        )

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
