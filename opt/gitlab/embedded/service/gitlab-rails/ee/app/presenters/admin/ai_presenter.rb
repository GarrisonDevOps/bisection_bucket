# frozen_string_literal: true

module Admin
  class AiPresenter
    include Gitlab::Utils::StrongMemoize
    include GitlabSubscriptions::CodeSuggestionsHelper

    delegate :disabled_direct_code_suggestions?,
      :duo_availability,
      :enabled_expanded_logging,
      :gitlab_dedicated_instance?,
      :instance_level_ai_beta_features_enabled?,
      :model_prompt_cache_enabled?,
      to: :application_settings

    delegate :amazon_q_ready?,
      :duo_core_features_enabled?,
      :duo_workflow_service_account_user,
      to: :ai_settings

    delegate :subscription_name,
      :starts_at,
      :expires_at,
      to: :license,
      allow_nil: true

    def initialize(current_user)
      @current_user = current_user
    end

    def settings
      {
        agentic_chat_verification_check_enabled: agentic_chat_verification_check_enabled?,
        expose_duo_agent_platform_service_url: expose_duo_agent_platform_service_url?,
        are_experiment_settings_allowed: experiments_settings_allowed?,
        are_prompt_cache_settings_allowed: true,
        beta_self_hosted_models_enabled: beta_self_hosted_models_enabled,
        can_manage_self_hosted_models: can_manage_self_hosted_models?,
        can_manage_instance_model_selection: can_manage_instance_model_selection?,
        direct_code_suggestions_enabled: !disabled_direct_code_suggestions?,
        duo_availability: duo_availability,
        are_duo_core_features_enabled: duo_core_features_enabled?,
        enabled_expanded_logging: enabled_expanded_logging,
        experiment_features_enabled: instance_level_ai_beta_features_enabled?,
        is_bulk_add_on_assignment_enabled: true,
        is_saas: saas?,
        show_sm_purchase_button: license.nil? ||
          license&.trial? ||
          License.has_active_gitlab_credits_add_on?,
        is_sm_trial: license&.trial?,
        prompt_cache_enabled: model_prompt_cache_enabled?,
        subscription_name: subscription_name,
        gitlab_credits_dashboard_path: gitlab_credits_dashboard_path,
        self_managed_purchase_credits_path: url_helpers.subscription_portal_self_managed_purchase_credits_url
      }.merge(duo_amazon_q_add_on_data, duo_paths)
        .transform_values(&:to_s)
        .merge(
          **duo_workflow_service_account,
          **duo_add_on_data
        )
    end

    private

    def expose_duo_agent_platform_service_url?
      ::Ability.allowed?(@current_user, :update_dap_self_hosted_model)
    end

    def duo_paths
      {
        add_duo_pro_seats_url: add_duo_pro_seats_url(subscription_name),
        duo_configuration_path: url_helpers.admin_gitlab_duo_configuration_index_path,
        duo_seat_utilization_path: url_helpers.admin_gitlab_duo_seat_utilization_index_path,
        duo_instance_model_selection_path: url_helpers.admin_gitlab_duo_model_selection_index_path,
        redirect_path: url_helpers.admin_gitlab_duo_path
      }
    end

    def duo_add_on_data
      {
        duo_add_on_end_date: duo_pro_or_duo_enterprise_add_on_purchase&.expires_on,
        duo_add_on_start_date: duo_pro_or_duo_enterprise_add_on_purchase&.started_at
      }
    end

    def duo_amazon_q_add_on_data
      return {} unless ::Ai::AmazonQ.feature_available?

      {
        amazon_q_auto_review_enabled: amazon_q_integration&.auto_review_enabled.present?,
        amazon_q_configuration_path: url_helpers.edit_admin_application_settings_integration_path(:amazon_q),
        amazon_q_ready: amazon_q_ready?
      }
    end

    def amazon_q_integration
      ::Integrations::AmazonQ.for_organization(ai_settings.organization_id).first
    end

    def duo_workflow_enabled?
      ::Ai::DuoWorkflow.available?
    end

    def can_manage_instance_model_selection?
      ::Ability.allowed?(@current_user, :manage_instance_model_selection)
    end

    def saas?
      Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
    end

    def experiments_settings_allowed?
      ::GitlabSubscriptions::AddOnPurchase.active_duo_add_ons_exist?(:instance)
    end

    def beta_self_hosted_models_enabled
      ::Ai::TestingTermsAcceptance.has_accepted?
    end

    def can_manage_self_hosted_models?
      ::Ability.allowed?(@current_user, :manage_self_hosted_models_settings)
    end

    def agentic_chat_verification_check_enabled?
      ::Ai::DuoAgentPlatformVerificationCheck.agentic_chat_verification_check_enabled?(@current_user)
    end

    def duo_workflow_service_account
      {
        duo_workflow_service_account: duo_workflow_service_account_user
          &.slice(:id, :username, :name, :avatar_url)
          &.to_json
      }
    end

    def url_helpers
      Gitlab::Routing.url_helpers
    end

    def license
      License.current
    end
    strong_memoize_attr :license

    def application_settings
      Gitlab::CurrentSettings.expire_current_application_settings
      Gitlab::CurrentSettings.current_application_settings
    end
    strong_memoize_attr :application_settings

    def ai_settings
      # rubocop:disable Gitlab/AvoidCurrentOrganization -- admin-area presenter; organization is assigned by the request middleware
      ::Ai::Setting.for_organization_read_only(::Current.organization)
      # rubocop:enable Gitlab/AvoidCurrentOrganization
    end
    strong_memoize_attr :ai_settings

    def duo_pro_or_duo_enterprise_add_on_purchase
      ::GitlabSubscriptions::Duo.active_self_managed_duo_pro_or_enterprise
    end
    strong_memoize_attr :duo_pro_or_duo_enterprise_add_on_purchase

    def gitlab_credits_dashboard_available?
      return false if Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      License.gitlab_credits_entitled?
    end

    def gitlab_credits_dashboard_path
      return unless gitlab_credits_dashboard_available?

      url_helpers.admin_gitlab_credits_dashboard_index_path
    end
  end
end
