# frozen_string_literal: true

module EE
  module ProjectsController
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    SEC_AI_WORKFLOW_ALLOWED_SETTING_ATTRIBUTES = [
      :duo_sast_vr_workflow_enabled,
      :duo_sast_fp_detection_enabled,
      :duo_secret_detection_fp_enabled,
      :duo_vulnerability_context_analysis_enabled
    ].freeze

    prepended do
      include GeoInstrumentation

      before_action :log_download_export_audit_event, only: [:download_export]

      skip_before_action :authorize_admin_project!, if: -> { sec_ai_workflow_setting_update? }
      before_action :authorize_sec_ai_workflow_setting!, only: [:update], if: -> { sec_ai_workflow_setting_in_params? }

      before_action do
        push_licensed_feature(:remote_development)
        push_frontend_ability(ability: :read_code_navigation, resource: @project, user: current_user)
        push_frontend_feature_flag(:blame_agent_sessions, @project)
        push_frontend_feature_flag(:duo_secret_detection_false_positive, @project, type: :beta)
      end

      before_action only: [:show, :edit] do
        push_saas_feature(:group_project_permanent_deletion_confirmation)
        push_dedicated_feature(:group_project_permanent_deletion_confirmation)
      end

      before_action only: [:edit] do
        push_frontend_feature_flag(:policy_store_setting_enforcement, @project.root_ancestor)
      end

      feature_category :groups_and_projects, [:transfer_personal]
    end

    def transfer_personal
      return access_denied! unless can?(current_user, :change_namespace, @project)

      response = ::Projects::TransferPersonalService.new(
        @project,
        current_user,
        { organization_id: Current.organization.id }
      ).execute

      if response.success?
        render json: {
          redirect_to: group_billings_path(@project.root_ancestor),
          group_name: @project.root_ancestor.name
        }, status: :ok
      else
        render json: { message: response.message }, status: :unprocessable_entity
      end
    end

    override :project_feature_attributes
    def project_feature_attributes
      super + [:requirements_access_level]
    end

    override :project_params_attributes
    def project_params_attributes
      if restrict_params_to_sec_ai_workflow_setting?
        return [{ project_setting_attributes: SEC_AI_WORKFLOW_ALLOWED_SETTING_ATTRIBUTES }]
      end

      super + project_params_ee
    end

    override :project_params
    def project_params(attributes: [])
      if restrict_params_to_sec_ai_workflow_setting?
        return sec_ai_workflow_setting_params
      end

      super.tap do |project_attrs|
        normalize_pipeline_execution_policy_bot_access_file_patterns!(project_attrs)
      end
    end

    override :custom_import_params
    def custom_import_params
      custom_params = super
      ci_cd_param = ci_cd_only_params.dig(:project, :ci_cd_only) || ci_cd_only_params[:ci_cd_only]

      custom_params[:ci_cd_only] = ci_cd_param if ci_cd_param == 'true'
      custom_params
    end

    override :active_new_project_tab
    def active_new_project_tab
      project_params[:ci_cd_only] == 'true' ? 'ci_cd_only' : super
    end

    private

    def ci_cd_only_params
      params.permit(:ci_cd_only, project: :ci_cd_only)
    end

    # This method allows security managers to update project level setting of SEC AI features
    # (e.g. SAST Vulnerability Resolution, False Positive Detection).
    # To prevent security managers from updating other project settings,
    # we only allow updating settings listed in SEC_AI_WORKFLOW_ALLOWED_SETTING_ATTRIBUTES.
    # If adding new settings, ensure param filtering is applied in restrict_params_to_sec_ai_workflow_setting?.
    # This implementation is part of: https://gitlab.com/groups/gitlab-org/-/work_items/21725.
    def sec_ai_workflow_setting_in_params?
      setting_attrs = params
        .permit(project: { project_setting_attributes: SEC_AI_WORKFLOW_ALLOWED_SETTING_ATTRIBUTES })
        .dig(:project, :project_setting_attributes)
      return false unless setting_attrs

      setting_attrs.key?(:duo_sast_vr_workflow_enabled) ||
        setting_attrs.key?(:duo_sast_fp_detection_enabled) ||
        setting_attrs.key?(:duo_secret_detection_fp_enabled) ||
        setting_attrs.key?(:duo_vulnerability_context_analysis_enabled)
    end

    def sec_ai_workflow_setting_update?
      action_name == 'update' && sec_ai_workflow_setting_in_params?
    end

    # CE `project_params` merges `import_url` in after `permit`, bypassing the allowed list.
    def sec_ai_workflow_setting_params
      params.require(:project).permit(project_params_attributes)
    end

    def authorize_sec_ai_workflow_setting!
      return if can?(current_user, :update_duo_setting, project)
      return if can_update_sec_ai_workflow_settings?

      access_denied!
    end

    def restrict_params_to_sec_ai_workflow_setting?
      return false if can?(current_user, :update_duo_setting, project)

      can_update_sec_ai_workflow_settings?
    end

    def can_update_sec_ai_workflow_settings?
      can?(current_user, :update_sec_ai_workflow_settings, project)
    end

    override :project_setting_attributes
    def project_setting_attributes
      attributes = base_project_setting_attributes
      attributes += licensed_feature_attributes
      attributes += duo_feature_attributes

      super + attributes
    end

    def base_project_setting_attributes
      %i[
        prevent_merge_without_jira_issue
        cve_id_request_enabled
        product_analytics_data_collector_host
        cube_api_base_url
        cube_api_key
        product_analytics_configurator_connection_string
        merge_request_title_regex
        merge_request_title_regex_description
      ]
    end

    def licensed_feature_attributes
      attributes = []

      if project&.licensed_feature_available?(:external_status_checks)
        attributes << :only_allow_merge_if_all_status_checks_passed
      end

      if ::Security::PolicyAvailability.available?(project, :security_orchestration_policies)
        attributes << :spp_repository_pipeline_access
        attributes << :pipeline_execution_policy_bot_access_enabled
        attributes << :pipeline_execution_policy_bot_access_group_id
        attributes << { pipeline_execution_policy_bot_access_file_patterns: [] }
      end

      if project&.licensed_feature_available?(:ai_workflows)
        attributes << :duo_remote_flows_enabled
      end

      add_duo_workflow_attributes(attributes)
      attributes
    end

    def duo_feature_attributes
      attributes = []

      attributes << { duo_context_exclusion_settings: { exclusion_rules: [] } }

      unless project&.project_setting&.duo_features_enabled_locked?
        attributes << :duo_features_enabled
      end

      attributes << :duo_sast_fp_detection_enabled
      attributes << :duo_vulnerability_context_analysis_enabled

      attributes << :duo_dependency_bump_breaking_changes_enabled

      if ::Feature.enabled?(:duo_secret_detection_false_positive, project)
        attributes << :duo_secret_detection_fp_enabled
      end

      attributes << :duo_sast_vr_workflow_enabled

      attributes
    end

    def add_duo_workflow_attributes(attributes)
      return unless project&.licensed_feature_available?(:ai_workflows)

      attributes << :duo_remote_flows_enabled
      attributes << :duo_foundational_flows_enabled if flow_execution_enabled_before_or_after_update?
      attributes << :duo_scheduled_triggers_enabled if scheduled_triggers_attribute_permitted?

      attributes << :tool_approval_for_session_enabled
      attributes << :duo_auto_mode_enabled
      attributes << :dap_session_tracking_enabled if project.project_setting.dap_session_tracking_available?
    end

    def scheduled_triggers_attribute_permitted?
      return false if project.project_setting.duo_scheduled_triggers_enabled_locked?

      flow_execution_enabled_before_or_after_update?
    end

    def flow_execution_enabled_before_or_after_update?
      return true if project.duo_remote_flows_enabled

      submitted = params
        .permit(project: { project_setting_attributes: [:duo_remote_flows_enabled] })
        .dig(:project, :project_setting_attributes, :duo_remote_flows_enabled)

      ::Gitlab::Utils.to_boolean(submitted, default: false)
    end

    def project_params_ee
      attrs = %i[
        approvals_before_merge
        issues_template
        merge_requests_template
        repository_size_limit
        reset_approvals_on_push
        ci_cd_only
        use_custom_template
        require_password_to_approve
        group_with_project_templates_id
      ]

      attrs << :merge_pipelines_enabled if allow_merge_pipelines_params?
      attrs << :merge_trains_enabled if allow_merge_trains_params?
      attrs << :merge_trains_skip_train_allowed if allow_merge_trains_params?
      attrs << :merge_train_enforcement if allow_merge_trains_params?
      attrs << :max_pipelines_per_merge_train if allow_merge_trains_params?

      attrs += merge_request_rules_params

      if project&.feature_available?(:auto_rollback)
        attrs << :auto_rollback_enabled
      end

      if project&.feature_available?(:project_level_analytics_dashboard)
        attrs << { analytics_dashboards_pointer_attributes: [:id, :target_project_id, :_destroy] }
      end

      if ::Ai::AmazonQ.connected?
        attrs << :amazon_q_auto_review_enabled
      end

      if allow_mirror_params?
        attrs + mirror_params
      else
        attrs
      end
    end

    def normalize_pipeline_execution_policy_bot_access_file_patterns!(project_attrs)
      setting_attrs = project_attrs[:project_setting_attributes]
      return unless setting_attrs
      return unless setting_attrs.key?(:pipeline_execution_policy_bot_access_enabled)
      return unless ::Gitlab::Utils.to_boolean(setting_attrs[:pipeline_execution_policy_bot_access_enabled])

      setting_attrs[:pipeline_execution_policy_bot_access_file_patterns] ||= []
    end

    def mirror_params
      %i[
        mirror
        mirror_trigger_builds
      ]
    end

    def allow_mirror_params?
      if @project
        can?(current_user, :admin_mirror, @project)
      else
        ::Gitlab::CurrentSettings.current_application_settings.mirror_available || current_user&.admin?
      end
    end

    def merge_request_rules_params
      attrs = []

      if can?(current_user, :modify_merge_request_committer_setting, project)
        attrs << :merge_requests_disable_committers_approval
      end

      if can?(current_user, :modify_approvers_rules, project)
        attrs << :disable_overriding_approvers_per_merge_request
      end

      if can?(current_user, :modify_merge_request_author_setting, project)
        attrs << :merge_requests_author_approval
      end

      attrs
    end

    def allow_merge_pipelines_params?
      project&.feature_available?(:merge_pipelines)
    end

    def allow_merge_trains_params?
      project&.feature_available?(:merge_trains)
    end

    def log_audit_event(message:, event_type:)
      audit_context = {
        name: event_type,
        author: current_user,
        target: project,
        scope: project,
        message: message,
        ip_address: request.remote_ip
      }

      ::Gitlab::Audit::Auditor.audit(audit_context)
    end

    def log_download_export_audit_event
      return if current_user.can_admin_all_resources? && ::Gitlab::CurrentSettings.silent_admin_exports_enabled?

      log_audit_event(message: 'Export file download started', event_type: 'project_export_file_download_started')
    end
  end
end
