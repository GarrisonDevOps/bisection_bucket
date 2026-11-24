# frozen_string_literal: true

module EE
  module WebHooks
    module DestroyService
      extend ::Gitlab::Utils::Override
      include ::WebHooks::AuditHelpers

      private

      override :after_destroy
      def after_destroy(web_hook)
        result = super
        log_audit_event(web_hook)
        result
      end

      def log_audit_event(web_hook)
        audit_context = {
          name: "webhook_destroyed",
          author: current_user,
          scope: hook_audit_scope(web_hook),
          target: web_hook,
          message: "Deleted #{web_hook.model_name.human.downcase}",
          target_details: "Hook #{web_hook.id}",
          additional_details: hook_audit_details(web_hook)
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
