# frozen_string_literal: true

module EE
  module IntegrationsHelper
    extend ::Gitlab::Utils::Override

    override :project_jira_issues_integration?
    def project_jira_issues_integration?
      @project.jira_issues_integration_available? && @project.jira_integration&.issues_enabled
    end

    override :integration_form_data
    def integration_form_data(integration, project: nil, group: nil, organization: nil)
      form_data = super

      if integration.is_a?(Integrations::Jira)
        form_data.merge!(
          show_jira_issues_integration: (project || group)&.jira_issues_integration_available?.to_s,
          show_jira_vulnerabilities_integration: integration.jira_vulnerabilities_integration_available?.to_s,
          enable_jira_issues: integration.issues_enabled.to_s,
          enable_jira_vulnerabilities: integration.jira_vulnerabilities_integration_enabled?.to_s,
          project_key: integration.project_key,
          project_keys: integration.project_keys_as_string,
          vulnerabilities_issuetype: integration.vulnerabilities_issuetype,
          customize_jira_issue_enabled: integration.customize_jira_issue_enabled.to_s
        )
      end

      if integration.is_a?(::Integrations::GoogleCloudPlatform::ArtifactRegistry)
        form_data.merge!(
          artifact_registry_path: project_google_cloud_artifact_registry_index_path(project),
          operating: integration.operating?.to_s
        )

        if project.google_cloud_platform_workload_identity_federation_integration&.operating?
          form_data.merge!(
            workload_identity_federation_project_number: project.google_cloud_platform_workload_identity_federation_integration.workload_identity_federation_project_number,
            workload_identity_pool_id: project.google_cloud_platform_workload_identity_federation_integration.workload_identity_pool_id
          )
        else
          form_data.merge!(
            editable: 'false',
            workload_identity_federation_path: edit_project_settings_integration_path(
              project, :google_cloud_platform_workload_identity_federation
            )
          )
        end
      end

      if integration.is_a?(::Integrations::GoogleCloudPlatform::WorkloadIdentityFederation)
        form_data[:wlif_issuer] = ::Integrations::GoogleCloudPlatform::WorkloadIdentityFederation.wlif_issuer_url(group || project)
        form_data[:jwt_claims] = ::Integrations::GoogleCloudPlatform::WorkloadIdentityFederation.jwt_claim_mapping_script_value
      end

      if integration.is_a?(::Integrations::AmazonQ)
        form_data[:amazon_q] = amazon_q_data(integration)
      end

      form_data.merge!(slack_duo_form_data(integration, project || group, organization))
    end

    # GitLab Duo on a GitLab for Slack page: the top-level group's lists its workspaces, a subgroup's points to where
    # it's decided. A later page ("Show more", `offset`) has only its rows and how many are left; `updated_team_id`
    # adds that workspace's row, wherever it is in the list, after a change.
    def slack_duo_data(integration, offset: 0, updated_team_id: nil)
      parent = integration.parent
      installation = ::Integrations::SlackWorkspace::DuoWorkspacesPresenter.installation_for(integration)
      return slack_duo_pointer_data(parent, installation) unless parent.is_a?(::Group) && parent.root?

      workspaces = ::Integrations::SlackWorkspace::DuoWorkspacesPresenter.new(
        group: parent, current_user: current_user, own_installation: installation, offset: offset
      )
      rows = slack_duo_rows_with_fix_links(workspaces.rows, parent, installation&.team_id)
      return { workspaces: rows, more_count: workspaces.more_count } if offset.to_i > 0

      can_update = can?(current_user, :update_duo_in_slack, parent)

      data = {
        scope: :group,
        state: rows.empty? ? :not_connected : :workspaces,
        own_team_id: workspaces.own_row&.dig(:team_id),
        workspaces: rows,
        more_count: workspaces.more_count,
        requirements: slack_duo_requirements(parent, workspaces, can_update),
        seats_required: can_update && ::Integrations::SlackWorkspace::DuoRequirements.seats_required?(parent),
        update_path: (duo_group_group_settings_slack_path(parent) if can_update),
        workspaces_path: duo_group_group_settings_slack_path(parent),
        admin_integration_path: slack_duo_admin_integration_path,
        **slack_duo_fix_paths(parent)
      }
      data[:updated_workspace] = slack_duo_row(parent, updated_team_id, installation) if updated_team_id
      data
    end

    # The section and its endpoints check the same. The page's own top-level group decides, not the viewer's
    # other groups: it's where GitLab Duo would run.
    # GA on GitLab.com. Self-Managed and Dedicated keep the experiment and beta opt-in until GA there.
    def slack_duo_group_feature_available?(container)
      root = container.root_ancestor

      ::Integrations::SlackWorkspace::Workspace.duo_group_feature_enabled?(root) &&
        (::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) || root.duo_beta_flows_enabled?)
    end

    def slack_duo_admin_feature_available?
      ::Integrations::SlackWorkspace::Workspace.duo_group_feature_enabled?(nil) &&
        ::Gitlab::CurrentSettings.instance_level_ai_beta_features_enabled?
    end

    override :slack_integration_destroy_confirm_message
    def slack_integration_destroy_confirm_message(integration)
      note = slack_duo_release_note(integration)
      note ? safe_join([super, tag.p(note)]) : super
    end

    def slack_duo_admin_data(organization)
      data = {
        scope: :admin,
        update_path: duo_group_admin_application_settings_slack_path,
        instance_settings_path: admin_gitlab_duo_configuration_index_path
      }
      installation = ::SlackIntegration.with_bot.instance_level_in(organization).first
      return data.merge(state: :not_connected) unless installation

      duo_group = slack_duo_instance_group(installation.team_id)
      mentions_ok = installation.authorized_scope_names.include?(::SlackIntegration::SCOPE_APP_MENTIONS_READ)

      data.merge(
        state: duo_group ? :on : :off,
        team_id: installation.team_id,
        team_name: installation.team_name,
        duo_group: ::Integrations::SlackWorkspace::DuoGroupReference.for(duo_group, current_user),
        slack_permissions_ok: mentions_ok,
        reinstall_path: (edit_admin_application_settings_integration_path(:gitlab_slack_application) unless mentions_ok),
        requirements: duo_group ? ::Integrations::SlackWorkspace::DuoRequirements.new(duo_group).checks : [],
        seats_required: ::Integrations::SlackWorkspace::DuoRequirements.seats_required?(nil),
        group_settings_path: duo_group&.duo_settings_path
      )
    end

    def jira_issues_show_data
      {
        issues_show_path: project_integrations_jira_issue_path(@project, params[:id], format: :json),
        issues_list_path: project_integrations_jira_issues_path(@project)
      }
    end

    override :integration_event_title
    def integration_event_title(event)
      return _('Vulnerability') if event == 'vulnerability'

      super
    end

    override :default_integration_event_description
    def default_integration_event_description(event)
      return s_("ProjectService|Trigger event when a new, unique vulnerability is recorded. (Note: This feature requires an Ultimate plan.)") if event == 'vulnerability'

      super
    end

    def external_issue_breadcrumb_title(issue_reference)
      strip_tags(issue_reference)
    end

    def zentao_issue_breadcrumb_link(issue)
      external_issue_breadcrumb_link('logos/zentao.svg', issue[:id], issue[:web_url], target: '_blank')
    end

    def zentao_issues_show_data
      {
        issues_show_path: project_integrations_zentao_issue_path(@project, params[:id], format: :json),
        issues_list_path: project_integrations_zentao_issues_path(@project)
      }
    end

    def amazon_q_data(integration)
      result = ::Ai::AmazonQ::IdentityProviderPayloadFactory.new.execute

      identity_provider =
        case result
        in { ok: payload }
          payload
        in { err: err }
          flash[:alert] = [
            s_('AmazonQ|Something went wrong retrieving the identity provider payload.'),
            err[:message]
          ].join(' ').squish

          {}
        end

      {
        submit_url: admin_ai_amazon_q_settings_path,
        disconnect_url: disconnect_admin_ai_amazon_q_settings_path,
        ready: ::Ai::Setting.for_organization_read_only(::Current.organization).amazon_q_ready.to_s,
        role_arn: ::Ai::Setting.for_organization_read_only(::Current.organization).amazon_q_role_arn,
        availability: ::Gitlab::CurrentSettings.duo_availability,
        auto_review_enabled: integration.auto_review_enabled.to_s
      }.merge(identity_provider)
    end

    def integrations_allow_list_data
      integrations = Integration.available_integration_names(include_blocked_by_settings: true).map do |integration|
        model = Integration.integration_name_to_model(integration)

        { title: model.title, name: model.to_param }
      end

      {
        integrations: integrations.to_json,
        allow_all_integrations: @application_setting.integrations['allow_all_integrations'].to_s,
        allowed_integrations: @application_setting.integrations['allowed_integrations'].to_json
      }
    end

    override :jira_specific_form_data
    def jira_specific_form_data(integration)
      return {} unless integration.is_a?(Integrations::Jira)

      super.merge!({
        jira_check_enabled: integration.jira_check_enabled.to_s,
        jira_exists_check_enabled: integration.jira_exists_check_enabled.to_s,
        jira_assignee_check_enabled: integration.jira_assignee_check_enabled.to_s,
        jira_status_check_enabled: integration.jira_status_check_enabled.to_s,
        jira_allowed_statuses_as_string: integration.jira_allowed_statuses_as_string
      })
    end

    private

    override :slack_duo_agent_available?
    # The Duo scopes read channel history. On GitLab.com's Duo group path, ask for them only where Duo can run:
    # not in a personal namespace, nor in a group without GitLab Duo Agent Platform.
    def slack_duo_agent_available?(user, parent)
      if parent && ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) &&
          ::Integrations::SlackWorkspace::Workspace.duo_group_feature_enabled?(parent)
        return ::Gitlab::Llm::StageCheck.available?(parent, :duo_workflow)
      end

      ::Ai::Catalog.user_can_access_experimental_and_beta_features?(user)
    end

    # The administrator decides where GitLab Duo runs for the instance's workspace, so the install page makes no
    # promise for a group install of it. An instance install has no group, so it follows the flag for the instance.
    override :slack_instance_workspace_data
    def slack_instance_workspace_data
      return unless current_user
      # Cheap checks first: GitLab.com has no instance installs, so it skips the experiment and beta lookup.
      return unless ::Integrations::SlackWorkspace::DuoGroupEligibility.instance_installs?
      return unless ::Integrations::SlackWorkspace::Workspace.duo_group_feature_enabled?(nil)
      return unless slack_duo_agent_available?(current_user, nil)

      name = ::SlackIntegration.with_bot.instance_level_in(::Current.organization).pick(:team_name)
      return unless name

      admin_path = edit_admin_application_settings_integration_path(:gitlab_slack_application) if
        current_user.can_admin_all_resources?

      { name: name, admin_path: admin_path }
    end

    # What removing this install can do to GitLab Duo in Slack: shown whenever the install is one GitLab Duo
    # depends on. Whether other installs stay isn't checked; that reads every group of the hierarchy on each
    # page load, so the note says "if" instead.
    def slack_duo_release_note(integration)
      installation = integration.slack_integration
      claim = installation && ::Integrations::SlackWorkspace::Workspace.for_team(installation.team_id)
      return unless claim
      return unless ::Integrations::SlackWorkspace::Workspace.duo_group_feature_enabled?(claim.duo_namespace)
      return unless slack_duo_depends_on?(integration, claim)

      slack_duo_release_message(integration, installation.team_name, claim.duo_namespace)
    end

    # The instance install when the administrator decides, or an install in the Duo group's hierarchy.
    def slack_duo_depends_on?(integration, claim)
      decided_by = ::Integrations::SlackWorkspace::DuoGroupEligibility.new(claim.duo_namespace, claim.team_id)
        .decided_by
      return decided_by == :admin if integration.instance_level?

      decided_by == :owner && integration.parent.root_ancestor.id == claim.duo_namespace_id
    end

    # Names the group only to someone who can see it.
    def slack_duo_release_message(integration, workspace, group)
      named = can?(current_user, :read_group, group)

      if integration.instance_level? && named
        format(s_('SlackIntegration|If %{group} has no install of %{workspace} of its own, ' \
          'GitLab Duo in Slack turns off for it.'), workspace: workspace, group: group.full_name)
      elsif integration.instance_level?
        format(s_('SlackIntegration|If its top-level group has no install of %{workspace} of its own, ' \
          'GitLab Duo in Slack turns off for it.'), workspace: workspace)
      elsif named
        format(s_('SlackIntegration|If this is the last install of %{workspace} in %{group}, ' \
          'GitLab Duo in Slack turns off for it.'), workspace: workspace, group: group.full_name)
      else
        format(s_('SlackIntegration|If this is the last install of %{workspace} in its top-level group, ' \
          'GitLab Duo in Slack turns off for it.'), workspace: workspace)
      end
    end

    # Only for the page's own form: the inherited settings form belongs to an ancestor, whose rows the viewer
    # may not be allowed to see. The instance-wide install has no parent.
    def show_slack_duo_section?(integration, page_parent)
      integration.is_a?(::Integrations::GitlabSlackApplication) &&
        integration.parent.present? &&
        integration.parent == page_parent &&
        slack_duo_group_feature_available?(integration.parent)
    end

    # The GitLab Duo section of a group or project page, or of the Admin area's page, for the GitLab for Slack app.
    def slack_duo_form_data(integration, page_parent, organization)
      if show_slack_duo_section?(integration, page_parent)
        { slack_duo: ::Gitlab::Json.dump(slack_duo_data(integration)) }
      elsif show_slack_duo_admin_section?(integration, page_parent, organization)
        { slack_duo_admin: ::Gitlab::Json.dump(slack_duo_admin_data(integration.organization)) }
      else
        {}
      end
    end

    # Only the Admin area's own page: group and project pages also render the instance integration as their
    # inherited form, and an organization's page isn't the organization the endpoint acts on.
    # The Admin area has no group to roll out to, so it follows the instance, like its endpoint.
    def show_slack_duo_admin_section?(integration, page_parent, organization)
      page_parent.nil? && organization.nil? &&
        integration.is_a?(::Integrations::GitlabSlackApplication) &&
        integration.instance_level? &&
        !!current_user&.can_admin_all_resources? &&
        slack_duo_admin_feature_available?
    end

    def slack_duo_requirements(group, workspaces, can_update)
      return [] unless can_update && workspaces.runs_here?

      ::Integrations::SlackWorkspace::DuoRequirements.new(group).checks
    end

    def slack_duo_pointer_data(parent, installation)
      data = { scope: :pointer, team_name: installation&.team_name }
      root = parent.root_ancestor
      return data.merge(state: :personal_namespace, notice: { key: :personal_namespace }) unless root.is_a?(::Group)

      team_id = installation&.team_id
      return data.merge(state: :not_connected, notice: { key: :not_connected }) unless team_id

      workspaces = ::Integrations::SlackWorkspace::DuoWorkspacesPresenter.new(
        group: root, current_user: current_user, own_installation: installation, only_team_id: team_id
      )
      state = workspaces.own_row[:state]
      # Only an off workspace's notice depends on whether the top-level group installed it.
      top_level_installed = state != :off || slack_duo_top_level_team_id(root) == team_id

      data.merge(state: state, notice: workspaces.pointer_notice(top_level_installed: top_level_installed))
    end

    # The workspace the top-level group's page has a toggle for.
    def slack_duo_top_level_team_id(root)
      ::Integrations::GitlabSlackApplication.for_group(root).first&.slack_integration&.team_id
    end

    # The row of one workspace on the top-level group page, wherever it is in the list.
    def slack_duo_row(group, team_id, installation)
      row = ::Integrations::SlackWorkspace::DuoWorkspacesPresenter.new(
        group: group, current_user: current_user, own_installation: installation, only_team_id: team_id
      ).rows.first

      slack_duo_rows_with_fix_links([row], group, installation&.team_id).first
    end

    # The app's permissions are fixed by reinstalling it: here for the page's own workspace, in the Admin area
    # for an instance workspace. Workspaces installed lower in the hierarchy get no link.
    def slack_duo_rows_with_fix_links(rows, group, own_team_id)
      rows.each do |row|
        next if row[:slack_permissions_ok]

        row[:reinstall_path] =
          if row[:installed_in].any? { |place| place[:kind] == :instance }
            slack_duo_admin_integration_path
          elsif row[:team_id] == own_team_id
            edit_group_settings_integration_path(group, :gitlab_slack_application)
          end
      end
    end

    def slack_duo_instance_group(team_id)
      claim = ::Integrations::SlackWorkspace::Workspace.for_team(team_id)
      return unless claim
      return unless ::Integrations::SlackWorkspace::DuoGroupEligibility.new(claim.duo_namespace, team_id).eligible?

      claim.duo_namespace
    end

    def slack_duo_admin_integration_path
      return unless current_user&.can_admin_all_resources?

      edit_admin_application_settings_integration_path(:gitlab_slack_application)
    end

    def slack_duo_fix_paths(group)
      {
        group_settings_path: group.duo_settings_path,
        instance_settings_path: (admin_gitlab_duo_configuration_index_path if current_user&.can_admin_all_resources?)
      }
    end

    # Use this method when dealing with issue data from external services
    # (like Jira or ZenTao).
    # Returns a sanitized `ActiveSupport::SafeBuffer` link.
    def external_issue_breadcrumb_link(img, text, href, options = {})
      icon = image_tag image_path(img), width: 15, height: 15, class: 'gl-mr-2'
      link = sanitize(
        link_to(
          strip_tags(text),
          strip_tags(href),
          options.merge(
            rel: 'noopener noreferrer',
            class: 'gl-flex gl-items-center gl-whitespace-nowrap'
          )
        ),
        tags: %w[a img],
        attributes: %w[target href src loading rel class width height]
      )

      [icon, link].join.html_safe
    end
  end
end
