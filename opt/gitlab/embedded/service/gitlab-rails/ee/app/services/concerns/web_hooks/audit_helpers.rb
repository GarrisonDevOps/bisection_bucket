# frozen_string_literal: true

module WebHooks
  # System hooks have no parent, so they use instance scope with the organization in the details.
  # No Organization audit scope exists yet: https://gitlab.com/gitlab-org/gitlab/-/work_items/607246
  module AuditHelpers
    private

    def hook_audit_scope(hook)
      return ::Gitlab::Audit::InstanceScope.new if hook.is_a?(::SystemHook)

      hook.parent || current_user
    end

    def hook_audit_details(hook)
      return {} unless hook.is_a?(::SystemHook)

      { organization_id: hook.organization_id }
    end
  end
end
