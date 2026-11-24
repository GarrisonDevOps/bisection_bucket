# frozen_string_literal: true

module MemberRoles
  class UpdateService < ::Authz::CustomRoles::BaseService
    def execute(role)
      @role = role

      return authorized_error unless allowed?

      update_role
    end

    private

    def update_role
      role.assign_attributes(params.slice(:name, :description,
        *MemberRole.all_customizable_permissions.keys))

      if role.save
        log_audit_event(action: :updated)
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
      return 'update_admin_custom_role' if role.admin_related_role?

      'update_custom_role'
    end
  end
end
