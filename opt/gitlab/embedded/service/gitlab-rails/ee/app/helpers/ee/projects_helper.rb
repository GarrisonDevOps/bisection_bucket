# frozen_string_literal: true

module EE
  module ProjectsHelper
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Utils::StrongMemoize

    override :sidebar_operations_paths
    def sidebar_operations_paths
      super + %w[
        oncall_schedules
      ]
    end

    override :project_permissions_settings
    def project_permissions_settings(project)
      setting = project.project_setting

      super.merge({
        requirementsAccessLevel: project.requirements_access_level,
        cveIdRequestEnabled: project.public? && setting.cve_id_request_enabled?,
        sppRepositoryPipelineAccess: setting.spp_repository_pipeline_access,
        pipelineExecutionPolicyBotAccessEnabled: setting.pipeline_execution_policy_bot_access_enabled,
        pipelineExecutionPolicyBotAccessFilePatterns: setting.pipeline_execution_policy_bot_access_file_patterns
      })
    end

    override :show_no_ssh_key_message?
    def show_no_ssh_key_message?(project)
      !project.root_ancestor.enforce_ssh_certificates? && super
    end

    override :project_permissions_panel_data
    def project_permissions_panel_data(project)
      super.merge({
        canManageSecretsManager: can?(current_user, :admin_project_secrets_manager, project),
        isSecretsManagerAvailable: secrets_manager_available_for_project?(project),
        topLevelGroupFullPath: project.root_ancestor.is_a?(Group) ? project.root_ancestor.full_path : '',
        requirementsAvailable: project.feature_available?(:requirements),
        requestCveAvailable: ::Gitlab.com?,
        cveIdRequestHelpPath: help_page_path('user/application_security/cve_id_request.md'),
        sppRepositoryPipelineAccessLocked: project.project_setting.spp_repository_pipeline_access_locked?,
        policySettingsAvailable: ::Security::PolicyAvailability.any_available?(project) &&
          ::Security::OrchestrationPolicyConfiguration.policy_management_project?(project),
        projectId: project.id
      }.merge(bot_access_settings_data(project)))
    end

    def bot_access_settings_data(project)
      unless ::Security::PolicyAvailability.available?(project, :security_orchestration_policies)
        return { botAccessSettingsAvailable: false }
      end

      {
        botAccessSettingsAvailable: true,
        botAccessGroupId: project.project_setting.pipeline_execution_policy_bot_access_group_id,
        botAccessRootGroupId: project.root_ancestor.is_a?(Group) ? project.root_ancestor.id : nil
      }
    end

    override :gitlab_duo_settings_data
    def gitlab_duo_settings_data(project)
      super.merge({
        duoFeaturesEnabled: project.project_setting.duo_features_enabled?,
        licensedAiFeaturesAvailable: project.licensed_ai_features_available?,
        amazonQAvailable: Ai::AmazonQ.connected?,
        amazonQAutoReviewEnabled: project.amazon_q_integration&.auto_review_enabled.present?,
        duoFeaturesLocked: project.project_setting.duo_features_enabled_locked?,
        duoContextExclusionSettings: project.project_setting.duo_context_exclusion_settings || {},
        initialDuoRemoteFlowsAvailability: project.duo_remote_flows_enabled,
        initialDuoFoundationalFlowsAvailability: project.duo_foundational_flows_enabled,
        initialDuoScheduledTriggersAvailability: project.duo_scheduled_triggers_enabled,
        initialDuoSastFalsePositiveDetectionEnabled: project.duo_sast_fp_detection_enabled,
        initialDuoSecretDetectionFpEnabled: project.duo_secret_detection_fp_enabled,
        initialDuoDependencyBumpBreakingChangesEnabled: project.duo_dependency_bump_breaking_changes_enabled,
        projectFullPath: project.full_path,
        projectGlobalId: project.to_global_id.to_s,
        initialDuoSastVrWorkflowEnabled: project.duo_sast_vr_workflow_enabled,
        initialDuoVulnerabilityContextAnalysisEnabled:
          project.project_setting.duo_vulnerability_context_analysis_enabled,
        ultimateFeaturesAvailable: project.root_ancestor.licensed_feature_available?(:ai_features),
        duoReadiness: duo_readiness_data(project),
        duoOrbit: duo_orbit_data(project),
        duoMcp: duo_mcp_data(project),
        visibleSettings: gitlab_duo_visible_settings(project)
      }.merge(duo_agent_platform_settings_data(project)))
    end

    override :default_url_to_repo
    def default_url_to_repo(project = @project)
      case default_clone_protocol
      when 'krb5'
        project.kerberos_url_to_repo
      else
        super
      end
    end

    override :extra_default_clone_protocol
    def extra_default_clone_protocol
      if alternative_kerberos_url? && current_user
        "krb5"
      else
        super
      end
    end

    def approvals_app_data(project = @project)
      {
        project_id: project.id,
        can_edit: can_modify_approvers.to_s,
        can_modify_author_settings: can_modify_author_settings.to_s,
        can_modify_commiter_settings: can_modify_commiter_settings.to_s,
        can_read_security_policies: can_read_security_policies.to_s,
        saml_provider_enabled: saml_provider_enabled_for_project?(project).to_s,
        project_path: expose_path(api_v4_projects_path(id: project.id)),
        approvals_path: expose_path(api_v4_projects_merge_request_approval_setting_path(id: project.id)),
        rules_path: expose_path(api_v4_projects_approval_rules_path(id: project.id)),
        allow_multi_rule: project.multiple_approval_rules_available?.to_s,
        eligible_approvers_docs_path: help_page_path('user/project/merge_requests/approvals/rules.md',
          anchor: 'eligible-approvers'),
        security_configuration_path: project_security_configuration_path(project),
        coverage_check_help_page_path: help_page_path('ci/testing/code_coverage/coverage_reporting.md',
          anchor: 'add-a-coverage-check-approval-rule'),
        group_name: project.root_ancestor.name,
        full_path: project.full_path,
        new_policy_path: expose_path(new_project_security_policy_path(project))
      }
    end

    def saml_provider_enabled_for_project?(project)
      group = project.root_ancestor
      return false unless group.is_a? Group

      !!group.saml_provider&.enabled?
    end

    def status_checks_app_data(project)
      {
        data: {
          project_id: project.id,
          status_checks_path: expose_path(api_v4_projects_external_status_checks_path(id: project.id))
        }
      }
    end

    def can_modify_approvers(project = @project)
      can?(current_user, :modify_approvers_rules, project)
    end

    def can_modify_author_settings(project = @project)
      can?(current_user, :modify_merge_request_author_setting, project)
    end

    def can_modify_commiter_settings(project = @project)
      can?(current_user, :modify_merge_request_committer_setting, project)
    end

    def can_read_security_policies(project = @project)
      can?(current_user, :read_security_orchestration_policies, project)
    end

    # Given the current GitLab configuration, check whether the GitLab URL
    # for Kerberos is going to be different than the HTTP URL
    def alternative_kerberos_url?
      ::Gitlab.config.alternative_gitlab_kerberos_url?
    end

    def can_change_push_rule?(push_rule, rule, context)
      return true if push_rule.is_a?(OrganizationPushRule)

      can?(current_user, :"change_#{rule}", context)
    end

    def ci_cd_projects_available?
      ::License.feature_available?(:ci_cd_projects) && import_sources_enabled?
    end

    override :remote_mirror_setting_enabled?
    def remote_mirror_setting_enabled?
      ::Gitlab::CurrentSettings.import_sources.any? &&
        ::License.feature_available?(:ci_cd_projects) &&
        (::Gitlab::CurrentSettings.current_application_settings.mirror_available ||
        current_user.can_admin_all_resources?)
    end

    def merge_pipelines_available?
      return false unless @project.builds_enabled?

      @project.feature_available?(:merge_pipelines)
    end

    def merge_trains_available?(project)
      return false unless project.builds_enabled?

      project.feature_available?(:merge_trains)
    end

    override :project_general_settings_data
    def project_general_settings_data(project)
      can_edit_repository_size_limit = current_user&.can_admin_all_resources? &&
        License.feature_available?(:repository_size_limit)

      super.merge(
        can_edit_repository_size_limit: can_edit_repository_size_limit.to_s,
        repository_size_limit_value: can_edit_repository_size_limit ? project.repository_size_limit.try(:to_mb) : nil,
        repository_size_limit_help_text: can_edit_repository_size_limit ? size_limit_message(project) : ''
      )
    end

    def size_limit_message(project)
      repository_size_limit_link = link_to _('Learn more'),
        help_page_path('administration/settings/account_and_limit_settings.md', anchor: 'repository-size-limit')

      message = if project.lfs_enabled?
                  _("Max size of this project's repository, including LFS files. %{repository_size_limit_link}.")
                else
                  _("Max size of this project's repository. %{repository_size_limit_link}.")
                end

      safe_format(message, repository_size_limit_link: repository_size_limit_link)
    end

    override :membership_locked?
    def membership_locked?
      group = @project.group

      return false unless group

      group.membership_lock? ||
        ::Gitlab::CurrentSettings.lock_memberships_to_ldap? ||
        ::Gitlab::CurrentSettings.lock_memberships_to_saml?
    end

    def group_project_templates_count(group_id)
      ::Projects::GroupTemplatesFinder.new(current_user, group_id).execute.count
    end

    override :show_built_in_project_templates_tab?
    def show_built_in_project_templates_tab?
      if @parent_group.is_a?(::Group)
        @parent_group.allow_built_in_project_templates?
      else
        ::Gitlab::CurrentSettings.current_application_settings
          .allow_instance_built_in_project_templates?
      end
    end

    def project_template_tab_state
      show_built_in = show_built_in_project_templates_tab?
      show_instance = !::Gitlab::Saas.feature_available?(:hide_project_instance_tab)
      activate_group = params[:tab] == 'group' || !(show_built_in || show_instance)

      {
        show_built_in: show_built_in,
        show_instance: show_instance,
        activate_group: activate_group,
        activate_built_in: show_built_in && !activate_group,
        activate_instance: !show_built_in && show_instance && !activate_group
      }
    end

    def base_project_security_dashboard_config(project)
      {
        has_vulnerabilities: 'false',
        has_jira_vulnerabilities_integration_enabled:
          (project.jira_integration&.configured_to_create_issues_from_vulnerabilities? || false).to_s,
        empty_state_svg_path: image_path('illustrations/empty-state/empty-secure-md.svg'),
        project_security_vulnerabilities_path: project_security_vulnerability_report_index_path(project),
        security_dashboard_empty_svg_path: image_path('illustrations/empty-state/empty-secure-md.svg'),
        no_vulnerabilities_svg_path: image_path('illustrations/empty-state/empty-search-md.svg'),
        project: { id: project.id, name: project.name },
        project_full_path: project.full_path,
        project_public: project.public?.to_s,
        security_configuration_path: project_security_configuration_path(@project),
        can_admin_vulnerability: can?(current_user, :admin_vulnerability, project).to_s,
        new_vulnerability_path: new_project_security_vulnerability_path(@project),
        dismissal_descriptions: dismissal_descriptions.to_json,
        hide_third_party_offers: ::Gitlab::CurrentSettings.current_application_settings.hide_third_party_offers?.to_s,
        operational_configuration_path: new_project_security_policy_path(@project),
        show_retention_alert: ::Gitlab.com?.to_s
      }.merge(security_dashboard_pipeline_data(project))
    end

    def project_security_dashboard_config_with_vulnerabilities(project)
      config = {
        has_vulnerabilities: 'true',
        vulnerabilities_export_endpoint:
          expose_path(api_v4_security_projects_vulnerability_exports_path(id: project.id)),
        vulnerabilities_pdf_export_endpoint:
        expose_path(api_v4_security_projects_vulnerability_exports_path(id: project.id,
          params: { export_format: :pdf })),
        new_project_pipeline_path: new_project_pipeline_path(project),
        scanners: VulnerabilityScanners::ListService.new(project).execute.to_json,
        can_view_false_positive: can_view_false_positive?,
        vulnerability_quota: vulnerability_quota_information(project),
        validity_checks_enabled: project.security_setting&.validity_checks_enabled&.to_s || 'false',
        manage_duo_settings_path: edit_project_path(project, anchor: 'js-gitlab-duo-settings'),
        experiment_features_enabled: (!!project.root_ancestor&.experiment_features_enabled).to_s,
        duo_agent_platform_available: ::Ai::DuoWorkflow.duo_agent_platform_available?(project).to_s,
        duo_sast_fp_detection_enabled: project.duo_sast_fp_detection_enabled.to_s,
        duo_vulnerability_context_analysis_enabled:
          project.project_setting.duo_vulnerability_context_analysis_enabled.to_s
      }

      config.merge!(security_dashboard_default_tracked_ref_data(project))

      base_project_security_dashboard_config(project).merge(config)
    end

    def project_security_dashboard_config(project)
      has_vulnerabilities = project.vulnerabilities.exists?

      return project_security_dashboard_config_with_vulnerabilities(project) if has_vulnerabilities

      base_project_security_dashboard_config(project)
    end

    def can_view_false_positive?
      project.licensed_feature_available?(:sast_fp_reduction).to_s
    end

    def can_create_feedback?(project, feedback_type)
      feedback = Vulnerabilities::Feedback.new(project: project, feedback_type: feedback_type)
      can?(current_user, :create_vulnerability_feedback, feedback)
    end

    def create_vulnerability_feedback_issue_path(project)
      return unless can_create_feedback?(project, :issue)

      project_vulnerability_feedback_index_path(project)
    end

    def create_vulnerability_feedback_merge_request_path(project)
      return unless can_create_feedback?(project, :merge_request)

      project_vulnerability_feedback_index_path(project)
    end

    def create_vulnerability_feedback_dismissal_path(project)
      return unless can_create_feedback?(project, :dismissal)

      project_vulnerability_feedback_index_path(project)
    end

    def show_discover_project_security?(project)
      !!current_user &&
        ::Gitlab.com? &&
        !project.feature_available?(:security_dashboard) &&
        can?(current_user, :admin_namespace, project.root_ancestor)
    end

    def show_compliance_frameworks_info?(project)
      project&.licensed_feature_available?(:custom_compliance_frameworks) &&
        project&.compliance_framework_settings&.first&.compliance_management_framework.present?
    end

    def compliance_center_path(project)
      project_security_compliance_dashboard_path(project, vueroute: "frameworks")
    end

    def show_duo_otel_button?(project, current_user)
      can?(current_user, :create_duo_otel_workflow, project)
    end

    def proxied_site
      ::Gitlab::Geo.proxied_site(request.env)
    end

    override :http_clone_url_to_repo
    def http_clone_url_to_repo(project)
      proxied_site ? geo_proxied_http_url_to_repo(proxied_site, project) : super
    end

    override :ssh_clone_url_to_repo
    def ssh_clone_url_to_repo(project)
      proxied_site ? geo_proxied_ssh_url_to_repo(proxied_site, project) : super
    end

    def project_transfer_app_data(project)
      {
        full_path: project.full_path
      }
    end

    def compliance_framework_data_attributes(project)
      return {} unless show_compliance_frameworks_info?(project)

      framework_data = {
        frameworks: []
      }

      framework_settings = project.compliance_framework_settings
      framework_settings.find_each do |settings|
        framework = settings.compliance_management_framework

        framework_data[:frameworks].push({
          compliance_framework_badge_color: framework.color,
          compliance_framework_badge_name: framework.name,
          compliance_framework_badge_title: framework.description
        })
      end

      framework_data
    end

    override :home_panel_data_attributes
    def home_panel_data_attributes
      project = @project.is_a?(ProjectPresenter) ? @project.project : @project

      super.merge(
        **compliance_framework_data_attributes(project)
      )
    end

    def pages_deployments_usage_quota_data(project)
      {
        full_path: project.full_path,
        deployments_count: project.pages_domain_level_parallel_deployments_count,
        deployments_limit: project.pages_parallel_deployments_limit,
        uses_namespace_domain: (!project.pages_unique_domain_enabled?).to_s,
        project_deployments_count: project.pages_parallel_deployments_count,
        domain: project.pages_hostname
      }
    end

    def can_use_pages_parallel_deployments?(project)
      Ability.allowed?(current_user, :update_pages, project) &&
        License.feature_available?(:pages_multiple_versions) &&
        project.pages_parallel_deployments_limit > 0 &&
        project.pages_parallel_deployments_count > 0
    end

    def show_pages_parallel_deployments_warning?(project)
      return false unless can_use_pages_parallel_deployments?(project)

      project.pages_domain_level_parallel_deployments_count >= (project.pages_parallel_deployments_limit * 0.8)
    end

    def show_pages_parallel_deployments_error?(project)
      return false unless can_use_pages_parallel_deployments?(project)

      project.pages_domain_level_parallel_deployments_count >= project.pages_parallel_deployments_limit
    end

    def pages_usage_quotas_link(project)
      "#{project_usage_quotas_path(project)}#pages-deployments-usage-tab"
    end

    private

    def duo_agent_platform_settings_data(project)
      {
        initialToolApprovalForSessionEnabled: project.project_setting.tool_approval_for_session_enabled?,
        toolApprovalForSessionLocked: project.project_setting.tool_approval_for_session_enabled_locked?,
        duoAutoModeAvailable: ::Feature.enabled?(:duo_auto_mode, project.root_ancestor, type: :beta),
        initialDuoAutoModeEnabled: project.project_setting.duo_auto_mode_enabled?,
        duoAutoModeLocked: project.project_setting.duo_auto_mode_enabled_locked?,
        dapSessionTrackingAvailable: project.project_setting.dap_session_tracking_available?,
        initialDapSessionTrackingEnabled: project.project_setting.dap_session_tracking_enabled?,
        aiAuditEventsStorageAvailable: true,
        aiAuditEventsStorageEnabled: project.project_setting.ai_audit_events_storage_enabled?
      }
    end

    # Mirrors the card's render conditions, so the readiness reads are only paid
    # when the card actually renders.
    def duo_readiness_card_renderable?(project)
      !::Ai::AmazonQ.connected? && can?(current_user, :update_duo_setting, project)
    end

    def duo_readiness_data(project)
      return {} unless duo_readiness_card_renderable?(project)

      readiness = ::Ai::DuoWorkflow::ProjectReadiness.new(project, current_user)
      agent_config_merge_request = readiness.agent_config_merge_request

      {
        platformEnabled: readiness.platform_enabled?,
        # No runner state here: the runner row loads it after first paint through the
        # duoWorkflowRunnerAvailable field, so the page request never pays for the scan.
        runnersPath: project_settings_ci_cd_path(project, anchor: 'js-runners-settings'),
        agentConfigPresent: readiness.agent_config_present?,
        agentConfigPath: duo_readiness_agent_config_path(project, readiness),
        agentConfigMergeRequestPath:
          agent_config_merge_request && project_merge_request_path(project, agent_config_merge_request),
        agentConfigWorkflowId: readiness.agent_config_workflow_id,
        generateAvailable: readiness.generate_available?,
        repositoryEmpty: readiness.repository_empty?,
        canGenerate: can?(current_user, :update_duo_setting, project),
        generatePath: project_settings_gitlab_duo_agent_config_path(project),
        isSaas: ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions),
        groupSettingsPath: duo_settings_path_for(project.root_ancestor),
        adminSettingsPath: can?(current_user, :admin_all_resources) ? admin_gitlab_duo_path : nil,
        rootGroupName: project.root_ancestor.is_a?(Group) ? project.root_ancestor.name : nil,
        foundationalFlows: duo_readiness_foundational_flows(project),
        foundationalAgents: duo_readiness_foundational_agents(project)
      }
    end

    # The foundational flows the top-level group picked. Projects cannot change the pick, so the
    # card lists it read-only, the way a subgroup's card does.
    def duo_readiness_foundational_flows(project)
      root_ancestor = project.root_ancestor
      return [] unless root_ancestor.is_a?(Group)

      flows = ::Ai::DuoSettings::FoundationalFlowsPresenter.new(root_ancestor)
      return [] unless flows.readiness_card_enabled?

      flows.selected_flows.map do |flow|
        { name: flow.translated_display_name, reference: flow.foundational_flow_reference }
      end
    end

    # The foundational agents the top-level group turned on. Only a GitLab.com top-level group picks
    # them, so the card lists them read-only, the way a subgroup's card does. Nil when there is no such
    # group to report: the card then shows no row, where an empty list says the group turned none on.
    def duo_readiness_foundational_agents(project)
      root_ancestor = project.root_ancestor
      return unless root_ancestor.is_a?(Group) && ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      agents = ::Ai::DuoSettings::FoundationalAgentsPresenter.new(root_ancestor, current_user: current_user)
      return unless agents.readiness_card_enabled?

      agents.selected_statuses.map { |status| { name: status[:name], reference: status[:reference] } }
    end

    def duo_orbit_data(project)
      return {} unless duo_readiness_card_renderable?(project)
      return {} unless ::Analytics::KnowledgeGraph.enabled_for?(current_user)

      root_ancestor = project.root_ancestor
      return {} unless root_ancestor.is_a?(Group)
      return {} unless ::Analytics::Orbit::Billing.account_for(root_ancestor).eligible?

      {
        enabled: project.knowledge_graph_indexing_enabled?,
        canEnable: can?(current_user, :update_knowledge_graph_setting, root_ancestor),
        canStartTrial: can?(current_user, :start_orbit_trial, root_ancestor),
        rootGroupPath: root_ancestor.full_path,
        graphPath: dashboard_orbit_path,
        settingsPath: group_settings_orbit_path(root_ancestor)
      }
    end

    # The count is deliberately absent: the row loads it after first paint via the
    # duoMcpServersCount GraphQL field, so the settings page request never pays for it.
    def duo_mcp_data(project)
      return {} unless duo_readiness_card_renderable?(project)
      return {} unless can?(current_user, :read_ai_catalog_mcp_server, project)

      {
        serversPath: project_automate_mcp_servers_path(project)
      }
    end

    def duo_readiness_agent_config_path(project, readiness)
      return unless readiness.agent_config_present?

      project_blob_path(
        project,
        tree_join(project.default_branch_or_main, ::Ai::DuoWorkflow::ProjectReadiness::AGENT_CONFIG_PATH)
      )
    end

    def gitlab_duo_visible_settings(project)
      return ['all'] if can?(current_user, :update_duo_setting, project)

      return [] unless can?(current_user, :update_sec_ai_workflow_settings, project)

      settings = []
      settings << 'duoSastVrWorkflowEnabled' if ::Feature.enabled?(:update_sast_vr_setting_permission, project)

      settings << 'duoSastFalsePositiveDetectionEnabled' if ::Feature.enabled?(
        :update_false_positive_detection_setting_permission,
        project)

      settings << 'duoSecretDetectionFpEnabled' if ::Feature.enabled?(
        :update_false_positive_detection_setting_permission,
        project)

      settings
    end

    def security_dashboard_default_tracked_ref_data(project)
      return {} unless Security::VAC.enabled?(project)

      default_branch_context = Security::ProjectTrackedContext.find_default_branch_context(project)
      return {} unless default_branch_context

      {
        default_branch_context: {
          id: default_branch_context.id.to_s,
          name: default_branch_context.context_name,
          ref_type: default_branch_context.context_type
        }.to_json
      }
    end

    def security_dashboard_pipeline_data(project)
      pipeline = project.vulnerability_statistic&.pipeline
      sbom_pipeline = project.latest_ingested_sbom_pipeline

      pipelines = {}

      if pipeline
        pipelines[:pipeline] = {
          id: pipeline.id,
          path: pipeline_path(pipeline),
          created_at: pipeline.created_at.to_fs(:iso8601),
          has_warnings: pipeline.has_security_report_ingestion_warnings?.to_s,
          has_errors: pipeline.has_security_report_ingestion_errors?.to_s,
          security_builds: {
            failed: {
              count: pipeline.latest_failed_security_builds.count,
              path: failures_project_pipeline_path(pipeline.project, pipeline)
            }
          }
        }
      end

      if sbom_pipeline
        pipelines[:sbom_pipeline] = {
          id: sbom_pipeline.id,
          path: pipeline_path(sbom_pipeline),
          created_at: sbom_pipeline.created_at.to_fs(:iso8601),
          has_warnings: "", # Not supported yet
          has_errors: sbom_pipeline.has_sbom_report_ingestion_errors?.to_s
        }
      end

      pipelines
    end

    def vulnerability_quota_information(project)
      quota = ::Vulnerabilities::Quota.new(project)

      {
        full: quota.full?.to_s,
        critical: quota.critical?.to_s,
        exceeded: quota.exceeded?.to_s
      }
    end
  end
end
