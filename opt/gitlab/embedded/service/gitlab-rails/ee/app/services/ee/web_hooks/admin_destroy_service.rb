# frozen_string_literal: true

module EE
  module WebHooks
    module AdminDestroyService
      extend ::Gitlab::Utils::Override
      include ::WebHooks::AuditHelpers

      private

      override :log_audit_event
      def log_audit_event(web_hook)
        audit_context = {
          name: "webhook_destroyed",
          author: ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
          # Not `hook_audit_scope`: this runs from a rake task with no acting user,
          # so its `current_user` fallback would hand `nil` to the auditor.
          scope: web_hook.parent || ::Gitlab::Audit::InstanceScope.new,
          target: web_hook,
          message: "Deleted #{web_hook.model_name.human.downcase} via rake task (#{rake_task.name})",
          target_details: "Hook #{web_hook.id}",
          additional_details: hook_audit_details(web_hook)
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
