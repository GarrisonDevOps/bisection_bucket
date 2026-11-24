# frozen_string_literal: true

module Security
  module Configuration
    class SetProjectSecretPushProtectionService < SetProjectSecuritySettingBaseService
      private

      def setting_key
        :secret_push_protection_enabled
      end

      def subject_project_ids
        [@subject.id] - @excluded_projects_ids
      end

      def audit
        message = "Secret push protection has been #{@enable ? 'enabled' : 'disabled'}"
        audit_context = build_audit_context(
          name: 'project_security_setting_updated',
          message: message
        )

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def post_update(project_ids)
        return unless project_ids.present?

        Security::AnalyzersStatus::ScheduleSettingChangedUpdateWorker.perform_async(project_ids, :secret_detection)
      end
    end
  end
end
