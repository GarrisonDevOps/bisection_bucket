# frozen_string_literal: true

module Admin
  class AiConfigurationPresenter
    include Gitlab::Utils::StrongMemoize

    delegate :disabled_direct_code_suggestions?,
      :duo_availability,
      :duo_remote_flows_availability,
      :duo_foundational_flows_availability,
      :duo_scheduled_automations_availability,
      :duo_custom_agents_availability,
      :duo_custom_flows_availability,
      :duo_external_agents_availability,
      :tool_approval_for_session_availability,
      :duo_auto_mode_availability,
      :duo_chat_expiration_column,
      :duo_chat_expiration_days,
      :duo_workflows_default_image_registry,
      :enabled_expanded_logging,
      :gitlab_dedicated_instance?,
      :instance_level_ai_beta_features_enabled,
      :model_prompt_cache_enabled?,
      :duo_template_project,
      :duo_template_project_available?,
      to: :application_settings

    delegate :duo_agent_platform_enabled,
      :ai_audit_events_streaming_enabled,
      :duo_token_usage_tracking_enabled,
      :duo_workflow_file_attachments_enabled,
      :duo_cli_enabled,
      :duo_core_features_enabled?,
      :foundational_agents_default_enabled,
      :ai_minimum_access_level_execute_with_fallback,
      :ai_minimum_access_level_execute_async_with_fallback,
      :include_recommended_allowed,
      :allow_all_unix_sockets,
      :allow_project_extension,
      :enforce_on_local_clients,
      :require_sandbox,
      :web_search_enabled,
      to: :ai_settings

    def initialize(current_user)
      @current_user = current_user
    end

    # rubocop:disable Metrics/AbcSize -- Assembles the full read-only Duo settings payload as one hash
    def settings
      settings_hash = {
        expose_duo_agent_platform_service_url: expose_duo_agent_platform_service_url?,
        are_experiment_settings_allowed: active_duo_add_ons_exist?,
        are_prompt_cache_settings_allowed: true,
        beta_self_hosted_models_enabled: beta_self_hosted_models_enabled,
        can_manage_self_hosted_models: can_manage_self_hosted_models?,
        can_read_namespace_duo_availability: can_read_namespace_duo_availability?,
        duo_instance_model_selection_path: url_helpers.admin_gitlab_duo_model_selection_index_path,
        show_gitlab_managed_model_alert: show_gitlab_managed_model_alert?,
        can_manage_aigw_timeout: can_manage_aigw_timeout?,
        can_configure_ai_logging: can_configure_ai_logging?,
        disabled_direct_connection_method: disabled_direct_code_suggestions?,
        code_completions_self_hosted: code_completions_self_hosted?,
        duo_availability: duo_availability,
        duo_agent_platform_enabled: duo_agent_platform_enabled,
        ai_audit_events_streaming_enabled: ai_audit_events_streaming_enabled,
        duo_token_usage_tracking_enabled: duo_token_usage_tracking_enabled,
        duo_workflow_file_attachments_enabled: duo_workflow_file_attachments_enabled,
        duo_cli_enabled: duo_cli_enabled,
        duo_remote_flows_availability: duo_remote_flows_availability,
        duo_foundational_flows_availability: duo_foundational_flows_availability,
        duo_scheduled_triggers_availability: duo_scheduled_automations_availability,
        duo_custom_agents_availability: duo_custom_agents_availability,
        duo_custom_flows_availability: duo_custom_flows_availability,
        duo_external_agents_availability: duo_external_agents_availability,
        tool_approval_for_session_availability: tool_approval_for_session_availability,
        duo_workflows_default_image_registry: duo_workflows_default_image_registry,
        duo_chat_expiration_column: duo_chat_expiration_column,
        duo_chat_expiration_days: duo_chat_expiration_days,
        duo_core_features_enabled: duo_core_features_enabled?,
        duo_pro_visible: active_duo_add_ons_exist?,
        enabled_expanded_logging: enabled_expanded_logging,
        experiment_features_enabled: instance_level_ai_beta_features_enabled,
        on_general_settings_page: false,
        prompt_cache_enabled: model_prompt_cache_enabled?,
        redirect_path: url_helpers.admin_gitlab_duo_path,
        toggle_beta_models_path: url_helpers.admin_ai_duo_self_hosted_toggle_beta_models_path,
        foundational_agents_default_enabled: foundational_agents_default_enabled,
        show_foundational_agents_availability: true,
        show_foundational_agents_per_agent_availability: true,
        show_duo_agent_platform_enablement_setting: true,
        foundational_agents_statuses: Gitlab::Json.dump(foundational_agents_statuses),
        ai_minimum_access_level_to_execute: ai_minimum_access_level_execute_with_fallback,
        ai_minimum_access_level_to_execute_async: ai_minimum_access_level_execute_async_with_fallback,
        include_recommended_allowed: include_recommended_allowed,
        allow_all_unix_sockets: allow_all_unix_sockets,
        allow_project_extension: allow_project_extension,
        enforce_on_local_clients: enforce_on_local_clients,
        require_sandbox: require_sandbox,
        web_search_enabled: web_search_enabled
      }

      settings_hash[:namespace_access_rules] = Gitlab::Json.dump(namespace_access_rules)
      settings_hash[:new_group_path] = url_helpers.new_group_path
      settings_hash[:duo_auto_mode_availability] = duo_auto_mode_availability if duo_auto_mode_flag_enabled?

      if duo_template_project_available?
        settings_hash[:duo_template_project] = duo_template_project_json
        settings_hash[:show_duo_template_project] = true
      else
        settings_hash[:show_duo_template_project] = false
      end

      settings_hash.transform_values(&:to_s)
    end
    # rubocop:enable Metrics/AbcSize

    private

    def duo_auto_mode_flag_enabled?
      ::Feature.enabled?(:duo_auto_mode, :instance)
    end

    def namespace_access_rules
      rules = ::Ai::FeatureAccessRule.duo_namespace_access_rules

      ::Ai::FeatureAccessRuleTransformer.transform(rules)
    end

    def expose_duo_agent_platform_service_url?
      ::Ability.allowed?(@current_user, :update_dap_self_hosted_model)
    end

    def active_duo_add_ons_exist?
      ::GitlabSubscriptions::AddOnPurchase.active_duo_add_ons_exist?(:instance)
    end

    def beta_self_hosted_models_enabled
      ::Ai::TestingTermsAcceptance.has_accepted?
    end

    def can_manage_self_hosted_models?
      ::Ability.allowed?(@current_user, :manage_self_hosted_models_settings)
    end

    def can_read_namespace_duo_availability?
      ::Ability.allowed?(@current_user, :read_namespace_duo_availability)
    end

    def show_gitlab_managed_model_alert?
      return false unless !!::License.current&.online_cloud_license?

      return false unless can_manage_self_hosted_models?

      !::Ai::Setting.self_hosted?
    end

    def code_completions_self_hosted?
      !!::Ai::FeatureSetting.find_by_feature(:code_completions)&.self_hosted?
    end

    def can_manage_aigw_timeout?
      ::Ability.allowed?(@current_user, :update_ai_gateway_timeout)
    end

    def can_configure_ai_logging?
      return false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      return false if gitlab_dedicated_instance?

      ::License.ai_features_available?
    end

    def url_helpers
      Gitlab::Routing.url_helpers
    end

    def application_settings
      Gitlab::CurrentSettings.expire_current_application_settings
      Gitlab::CurrentSettings.current_application_settings
    end
    strong_memoize_attr :application_settings

    def foundational_agents_statuses
      statuses = ::Organizations::Organization.default_organization&.foundational_agents_statuses
      statuses = reject_unavailable_orbit_agent(statuses)
      return statuses if ::License.feature_available?(:ai_features)

      statuses&.reject { |s| ::Ai::FoundationalChatAgent.ultimate_only_references.include?(s[:reference]) }
    end
    strong_memoize_attr :foundational_agents_statuses

    # Must run before the :ai_features early return: orbit_agent is not
    # ultimate_only, so the ultimate_only reject would never drop it there.
    def reject_unavailable_orbit_agent(statuses)
      return statuses if ::Analytics::KnowledgeGraph.enabled_for?(@current_user)

      statuses&.reject { |s| s[:reference] == 'orbit_agent' }
    end

    def ai_settings
      # rubocop:disable Gitlab/AvoidCurrentOrganization -- admin-area presenter; organization is assigned by the request middleware
      ::Ai::Setting.for_organization_read_only(::Current.organization)
      # rubocop:enable Gitlab/AvoidCurrentOrganization
    end
    strong_memoize_attr :ai_settings

    def duo_template_project_json
      project = duo_template_project
      return unless project

      {
        id: project.id,
        name: project.name,
        name_with_namespace: project.name_with_namespace,
        full_path: project.full_path,
        avatar_url: project.avatar_url
      }.to_json
    end
  end
end
