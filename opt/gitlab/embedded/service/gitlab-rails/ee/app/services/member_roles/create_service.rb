# frozen_string_literal: true

module MemberRoles
  class CreateService < ::Authz::CustomRoles::BaseService
    def execute
      return authorized_error unless allowed?

      @role = build_role
      if role.save
        log_audit_event(action: :created)
        collect_metrics

        success
      else

        error
      end
    end

    private

    def build_role
      organization_id = namespace ? nil : current_user.organization_id

      MemberRole.new(params.merge(namespace: namespace, organization_id: organization_id))
    end

    def allowed?
      subject = namespace || :global
      can?(current_user, :admin_member_role, subject)
    end

    def event_name
      # TODO: Remove this as part of https://gitlab.com/gitlab-org/gitlab/-/issues/555681
      return 'create_admin_custom_role' if role.admin_related_role?

      'create_custom_role'
    end
  end
end
