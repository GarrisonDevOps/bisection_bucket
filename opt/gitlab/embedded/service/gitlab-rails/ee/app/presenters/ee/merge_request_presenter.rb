# frozen_string_literal: true

module EE
  module MergeRequestPresenter
    extend ::Gitlab::Utils::Override
    extend ::Gitlab::Utils::DelegatorOverride

    include ::AuthHelper

    APPROVALS_WIDGET_FULL_TYPE = 'full'

    def api_approval_settings_path
      if expose_mr_approval_path?
        expose_path(api_v4_projects_merge_requests_approval_settings_path(id: project.id, merge_request_iid: merge_request.iid))
      end
    end

    def api_project_approval_settings_path
      if approval_feature_available?
        expose_path(api_v4_projects_approval_settings_path(id: project.id))
      end
    end

    def api_status_checks_path
      if expose_mr_status_checks?
        expose_path(api_v4_projects_merge_requests_status_checks_path(id: project.id, merge_request_iid: merge_request.iid))
      end
    end

    def merge_immediately_docs_path
      help_page_path('ci/pipelines/merge_trains.md', anchor: 'skip-the-merge-train-and-merge-immediately')
    end

    delegator_override :target_project
    def target_project
      merge_request.target_project.present(current_user: current_user)
    end

    def code_owner_rules_with_users
      @code_owner_rules ||= merge_request.approval_rules.code_owner.with_users.to_a
    end

    # Deprecated with epic https://gitlab.com/groups/gitlab-org/-/epics/19155
    delegator_override :approver_groups
    def approver_groups
      []
    end

    # Deprecated with epic https://gitlab.com/groups/gitlab-org/-/epics/19155
    delegator_override :approvers
    def approvers
      []
    end

    def suggested_approvers
      merge_request.approval_state.suggested_approvers(current_user: current_user)
    end

    override :approvals_widget_type
    def approvals_widget_type
      expose_mr_approval_path? ? APPROVALS_WIDGET_FULL_TYPE : super
    end

    def discover_project_security_path
      project_security_discover_path(project) if show_discover_project_security?(project)
    end

    def issue_keys
      return [] unless project.jira_integration.try(:active?)

      Atlassian::JiraIssueKeyExtractor.new(
        merge_request.title,
        merge_request.description,
        custom_regex: project.jira_integration.reference_pattern
      ).issue_keys
    end

    def saml_approval_path
      return if personal_namespace? # does not apply to personal projects

      return group_saml_path if group_requires_saml_auth_for_approval?

      instance_saml_path if instance_requires_saml_auth_for_approval?
    end

    def instance_saml_path
      approval_path = saml_approval_namespace_project_merge_request_path(
        project&.group,
        target_project,
        iid
      )

      expose_path(
        user_saml_omniauth_authorize_path(
          current_user,
          saml_providers_active_for_user.first, # TODO this will handle only the first SAML provider provider, not necesarily the SAML provider used for the current session
          redirect_to: approval_path
        )
      )
    end

    def user_saml_omniauth_authorize_path(*args)
      _, saml_provider, options = args
      path = URI("/users/auth/#{saml_provider}")
      path.query = URI.encode_www_form(options)
      path.to_s
    end

    def saml_providers_active_for_user
      return unless current_user

      current_user.identities.with_provider(saml_providers).pluck(:provider) # rubocop:disable CodeReuse/ActiveRecord  -- Using pluck here simplifies the query
    end

    def group_saml_path
      # Will not work with URL since the SSO controller will sanitize it
      saml_approval_redirect_path = saml_approval_namespace_project_merge_request_path(
        group,
        target_project,
        merge_request.iid)

      expose_path sso_group_saml_providers_path(
        root_group,
        token: root_group.saml_discovery_token,
        redirect: saml_approval_redirect_path
      )
    end

    def require_saml_auth_to_approve
      # require_password_to_approve setting is used to require password or SAML
      # re-auth, setting should be renamed via
      # https://gitlab.com/gitlab-org/gitlab/-/issues/431346

      return false unless mr_approval_setting_password_required?

      group_requires_saml_auth_for_approval? || instance_requires_saml_auth_for_approval?
    end

    private

    def root_group
      group.root_ancestor
    end

    def group
      target_project.namespace
    end

    def instance_requires_saml_auth_for_approval?
      # password authentication not allowed for instance
      # AND user is not a password-based omniauth user
      # AND user has a saml identity
      ::Gitlab::Auth::Saml::SsoEnforcer.new(
        user: current_user,
        session_timeout: 0.seconds
      ).access_restricted?
    end

    def group_requires_saml_auth_for_approval?
      # group saml enforced
      ::Gitlab::Auth::GroupSaml::SsoEnforcer.access_restricted?(
        user: current_user,
        resource: merge_request.project,
        session_timeout: 0.seconds
      )
    end

    def mr_approval_setting_password_required?
      return false if personal_namespace? # does not apply to personal projects

      ComplianceManagement::MergeRequestApprovalSettings::Resolver.new(
        root_group,
        project: target_project
      )
        .require_password_to_approve
        .value || merge_request.require_password_to_approve?
    end

    def expose_mr_status_checks?
      current_user.present? &&
        project.external_status_checks.applicable_to_branch(merge_request.target_branch).any?
    end

    def expose_mr_approval_path?
      approval_feature_available? && merge_request.iid
    end

    def personal_namespace?
      !group.is_a?(Group)
    end
  end
end

EE::MergeRequestPresenter.include_mod_with('ProjectsHelper')
