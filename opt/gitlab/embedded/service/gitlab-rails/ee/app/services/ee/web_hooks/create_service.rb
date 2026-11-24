# frozen_string_literal: true

module EE
  module WebHooks
    module CreateService
      extend ::Gitlab::Utils::Override
      include ::WebHooks::AuditHelpers

      private

      override :after_create
      def after_create(hook)
        result = super
        log_audit_event(hook)
        result
      end

      def log_audit_event(hook)
        audit_context = {
          name: "webhook_created",
          author: current_user,
          scope: hook_audit_scope(hook),
          target: hook,
          message: "Created #{hook.model_name.human.downcase}",
          target_details: "Hook #{hook.id}",
          additional_details: hook_audit_details(hook)
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
