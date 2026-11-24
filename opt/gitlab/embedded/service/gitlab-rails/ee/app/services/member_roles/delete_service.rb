# frozen_string_literal: true

module MemberRoles
  class DeleteService < ::Authz::CustomRoles::BaseService
    def execute(role)
      @role = role

      return authorized_error unless allowed?

      return error(message: 'Custom role linked with a security policy.') if role.dependent_security_policies.exists?

      if role.destroy
        log_audit_event(action: :deleted)
        collect_metrics

        success
      else
        error
      end
    end

    def allowed?
      can?(current_user, :admin_member_role, role)
    end

    def event_name
      # TODO: Remove this as part of https://gitlab.com/gitlab-org/gitlab/-/issues/555681
      return 'delete_admin_custom_role' if role.admin_related_role?

      'delete_custom_role'
    end
  end
end
