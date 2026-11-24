# frozen_string_literal: true

module EE
  module GlobalPolicy
    extend ActiveSupport::Concern

    prepended do
      include ::Gitlab::Utils::StrongMemoize

      condition(:operations_dashboard_available) do
        License.feature_available?(:operations_dashboard)
      end

      condition(:pages_size_limit_available) do
        License.feature_available?(:pages_size_limit)
      end

      condition(:export_user_permissions_available) do
        ::License.feature_available?(:export_user_permissions)
      end

      condition(:top_level_group_creation_enabled) do
        next true if ::Gitlab.com? && @user&.can_admin_all_resources?

        ::Gitlab::CurrentSettings.top_level_group_creation_enabled?
      end

      condition(:clickhouse_main_database_available) do
        ::Gitlab::ClickHouse.configured?
      end

      condition(:instance_devops_adoption_available) do
        ::License.feature_available?(:instance_level_devops_adoption)
      end

      condition(:runner_performance_insights_available) do
        ::License.feature_available?(:runner_performance_insights)
      end

      condition(:runner_upgrade_management_available) do
        License.feature_available?(:runner_upgrade_management)
      end

      condition(:instance_external_audit_events_enabled) do
        ::License.feature_available?(:external_audit_events)
      end

      condition(:code_suggestions_licensed) do
        next true if ::Gitlab.org_or_com?
        next true if ::GitlabSubscriptions::Duo.active_self_managed_gitlab_credits?

        ::License.feature_available?(:code_suggestions)
      end

      condition(:code_suggestions_enabled_for_user) do
        next false unless @user

        @user.allowed_to_use?(:code_suggestions)
      end

      condition(:ai_features_banned) do
        ::Gitlab::CurrentSettings.duo_never_on?
      end

      condition(:user_allowed_to_use_glab_ask_git_command) do
        next false unless @user

        @user.allowed_to_use?(:glab_ask_git_command, licensed_feature: :glab_ask_git_command)
      end

      rule { ~ai_features_banned & user_allowed_to_use_glab_ask_git_command }.policy do
        enable :access_glab_ask_git_command
      end

      condition(:duo_classic_chat_enabled_for_user) do
        next false unless @user

        @user.allowed_to_use?(:chat, unit_primitive_name: :duo_classic_chat)
      end

      condition(:duo_agentic_chat_enabled_for_user) do
        next false unless @user

        @user.allowed_to_use?(:agentic_chat, unit_primitive_name: :duo_chat)
      end

      condition(:user_belongs_to_paid_namespace) do
        next false unless @user

        @user.belongs_to_paid_namespace?
      end

      condition(:custom_roles_allowed) do
        ::License.feature_available?(:custom_roles)
      end

      condition(:default_roles_assignees_allowed) do
        ::License.feature_available?(:default_roles_assignees)
      end

      condition(:instance_model_configuration_allowed) do
        next false unless ::License.feature_available?(:self_hosted_models)

        has_duo_core_pro_or_enterprise =
          ::GitlabSubscriptions::AddOnPurchase.for_self_managed.for_duo_core_pro_or_enterprise.active.exists?

        has_duo_core_pro_or_enterprise || dap_self_hosted?
      end

      condition(:self_hosted_models_allowed) do
        next false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        next false unless self_hosted_enabled_for_dedicated?

        next false if ::Ai::AmazonQ.connected?

        ::GitlabSubscriptions::AddOnPurchase.for_self_managed.for_duo_enterprise.active.exists? || dap_self_hosted?
      end

      condition(:self_hosted_dap_allowed, scope: :global) do
        dap_self_hosted?
      end

      condition(:instance_model_selection_available) do
        next false if ::Ai::AmazonQ.connected?

        !::License.current&.offline_cloud_license?
      end

      condition(:model_selection_allowlist_available) do
        ::License.current&.online_cloud_license?
      end

      rule { ~anonymous & operations_dashboard_available }.enable :read_operations_dashboard

      condition(:ai_catalog_available, scope: :user) do
        ::Ai::Catalog.available_for_user?(@user)
      end

      rule { ai_catalog_available }.policy do
        enable :read_ai_catalog
        enable :read_ai_catalog_flow
      end

      condition(:abuse_notification_email_present, scope: :global) do
        ::Gitlab::CurrentSettings.current_application_settings.abuse_notification_email.present?
      end

      rule { ~anonymous & abuse_notification_email_present }.enable :report_ai_catalog_item

      condition(:remote_development_feature_licensed) do
        License.feature_available?(:remote_development)
      end

      condition(:has_admin_custom_role, scope: :user) do
        ::Gitlab::CustomRoles::Definition.admin.keys.any? do |ability|
          custom_role_ability(@user).allowed?(ability)
        end
      end

      ::Gitlab::CustomRoles::Definition.admin.each_key do |ability|
        desc "Admin custom role that enables #{ability.to_s.tr('_', ' ')}"
        condition(:"custom_role_enables_#{ability}") do
          custom_role_ability(@user).allowed?(ability)
        end
      end

      condition(:duo_core_features_available) do
        License.duo_core_features_available?
      end

      condition(:data_management_available) do
        License.feature_available?(:data_management) &&
          ::Gitlab::Geo.enabled?
      end

      # No :orbit license check: an unlicensed admin still opens the Admin Orbit
      # page, where it shows "not available" and a link to contact sales.
      condition(:admin_knowledge_graph_settings_available) do
        next false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        ::Analytics::KnowledgeGraph.enabled_for?(@user)
      end

      condition(:orbit_instance_eligible, scope: :global) do
        ::Analytics::Orbit::Billing.instance_account.eligible?
      end

      condition(:orbit_self_managed, scope: :global) do
        !::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      end

      # CDot bills the Orbit trial to the instance, so only an admin starts it.
      condition(:orbit_instance_trial_offered, scope: :global) do
        !::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) &&
          ::Analytics::KnowledgeGraph.service_configured? &&
          ::Analytics::Orbit::Billing.instance_account.trial_offered?
      end

      condition(:enterprise_user_disallowed_personal_snippets) { @user.enterprise_group&.disallow_personal_snippets? }

      rule { ~anonymous & remote_development_feature_licensed }.policy do
        enable :access_workspaces_feature
      end

      rule { admin & instance_devops_adoption_available }.policy do
        enable :manage_devops_adoption_namespaces
        enable :view_instance_devops_adoption
      end

      condition(:instance_secrets_manager_enrollment_allowed) do
        ::SecretsManagement::InstanceEnrollment.enrollment_allowed?
      end

      rule { admin & instance_secrets_manager_enrollment_allowed }.policy do
        enable :create_secrets_manager_enrollment
        enable :delete_secrets_manager_enrollment
        enable :read_secrets_manager_enrollment
      end

      condition(:instance_secrets_manager_paid_experience_allowed) do
        ::SecretsManagement::InstanceEnrollment.paid_experience_allowed?
      end

      # The instance-wide trial and paid add-on are billing actions on the
      # instance's subscription, so they are reserved for instance admins: a
      # top-level group Owner must not reach them through the group mutations.
      rule { admin & instance_secrets_manager_paid_experience_allowed }.policy do
        enable :start_secrets_manager_trial
        enable :read_secrets_manager_entitlement
        enable :enable_secrets_manager_add_on
      end

      rule { admin }.policy do
        enable :create_add_on_assignment
        enable :delete_add_on_assignment
        enable :read_add_on_purchase
        enable :delete_license
        enable :update_gitlab_subscription
        enable :update_compute_minutes_quota
        enable :read_admin_subscription
        enable :read_admin_data_management
        enable :read_knowledge_graph_setting
        enable :update_knowledge_graph_setting
        enable :read_all_geo
        enable :read_all_workspaces
        enable :read_cloud_connector_status
        enable :read_jobs_statistics
        enable :read_licenses
        enable :read_runner_usage
        enable :read_ldap_admin_role_link
        enable :read_namespace_duo_availability
        enable :create_ldap_admin_role_link
        enable :delete_ldap_admin_role_link
        enable :manage_self_hosted_models_settings
        enable :read_dap_self_hosted_model
        enable :update_dap_self_hosted_model
        enable :manage_instance_model_selection
        enable :read_model_selection_allowlist
        enable :update_model_selection_allowlist
        enable :read_enterprise_ai_analytics
        enable :update_subscription_usage_cap
        enable :read_subscription_usage
        enable :force_hard_delete_ai_catalog_item
        enable :clear_active_context_dead_queue
        enable :replay_active_context_dead_queue
        enable :update_ai_gateway_timeout
        enable :read_incident_management_oncall_schedule
        enable :read_incident_management_escalation_policy
      end

      rule { ~instance_model_configuration_allowed }.policy do
        prevent :manage_self_hosted_models_settings
        prevent :manage_instance_model_selection
      end

      rule { ~self_hosted_models_allowed }.prevent :manage_self_hosted_models_settings
      rule { ~instance_model_selection_available }.prevent :manage_instance_model_selection
      rule { ~self_hosted_dap_allowed }.policy do
        prevent :read_dap_self_hosted_model
        prevent :update_dap_self_hosted_model
      end

      rule { ~model_selection_allowlist_available }.policy do
        prevent :read_model_selection_allowlist
        prevent :update_model_selection_allowlist
      end

      rule { admin & custom_roles_allowed }.policy do
        enable :admin_member_role
        enable :view_member_roles
        enable :read_admin_role
        enable :create_admin_role
      end

      rule { admin & default_roles_assignees_allowed }.policy do
        enable :view_member_roles
      end

      rule { ~anonymous & custom_roles_allowed }.policy do
        enable :read_member_role
      end

      rule { admin & pages_size_limit_available }.enable :update_max_pages_size

      rule { ~runner_performance_insights_available }.policy do
        prevent :read_jobs_statistics
        prevent :read_runner_usage
      end

      rule { ~clickhouse_main_database_available }.prevent :read_runner_usage

      rule { ~anonymous }.policy do
        enable :view_productivity_analytics
      end

      rule { ~(admin | allow_to_manage_default_branch_protection) }.policy do
        prevent :create_group_with_default_branch_protection
      end

      rule { export_user_permissions_available & admin }.enable :export_user_permissions

      rule { can?(:create_group) }.enable :create_group_via_api
      rule { ~top_level_group_creation_enabled }.prevent :create_group_via_api

      rule { admin & instance_external_audit_events_enabled }.policy do
        enable :admin_instance_external_audit_events
        enable :update_audit_event_streaming_destination
      end

      rule do
        code_suggestions_licensed & ~ai_features_banned & code_suggestions_enabled_for_user
      end.enable :access_code_suggestions

      rule do
        ~ai_features_banned & duo_classic_chat_enabled_for_user
      end.enable :access_duo_classic_chat
      rule do
        ~ai_features_banned & duo_agentic_chat_enabled_for_user
      end.enable :access_duo_agentic_chat
      rule { can?(:access_duo_classic_chat) | can?(:access_duo_agentic_chat) }.enable :access_duo_entry_point

      rule { runner_upgrade_management_available | user_belongs_to_paid_namespace }.enable :read_runner_upgrade_status

      rule { security_policy_bot }.policy do
        enable :_access_api_as_internal_user
        enable :access_api
        enable :access_git
      end

      rule { has_admin_custom_role }.policy do
        enable :access_admin_area
        enable :read_application_statistics
      end

      rule { custom_role_enables_read_admin_cicd }.policy do
        enable :read_admin_cicd
      end

      rule { custom_role_enables_read_admin_monitoring }.policy do
        enable :read_admin_background_migrations
        enable :read_admin_data_management
        enable :read_admin_gitaly_servers
        enable :read_admin_health_check
        enable :read_admin_system_information
      end

      rule { custom_role_enables_read_admin_subscription }.policy do
        enable :read_admin_subscription
        enable :read_billable_member
        enable :read_licenses
      end

      rule { custom_role_enables_read_admin_users }.policy do
        enable :read_admin_users
        enable :read_user_access_level
      end

      # Instance auditors have no role YAML scope for instance-level permissions.
      rule { auditor }.enable :read_user_access_level

      rule { custom_role_enables_read_admin_groups }.policy do
        enable :read_admin_groups
      end

      rule { custom_role_enables_read_admin_projects }.policy do
        enable :read_admin_projects
      end

      rule { admin & duo_core_features_available }.policy do
        enable :update_duo_core_setting
      end

      condition(:direct_access_enabled) do
        !::Gitlab::CurrentSettings.disabled_direct_code_suggestions
      end

      condition(:allowed_to_use_model_proxy, scope: :user) do
        next false unless @user

        @user.allowed_to_use?(:duo_agent_platform, unit_primitive_name: :ai_gateway_model_provider_proxy) ||
          @user.duo_agent_platform_enabled_via_credits?
      end

      rule { direct_access_enabled & allowed_to_use_model_proxy }.policy do
        enable :create_third_party_agent_direct_access_token
      end

      rule { ~data_management_available }.prevent :read_admin_data_management

      rule { ~admin_knowledge_graph_settings_available }.policy do
        prevent :read_knowledge_graph_setting
        prevent :update_knowledge_graph_setting
      end

      # The Admin Orbit page opens without the license, but only an eligible instance changes the settings.
      rule { ~orbit_instance_eligible }.prevent :update_knowledge_graph_setting

      rule { admin & orbit_instance_trial_offered }.enable :start_orbit_trial
      rule { admin & orbit_self_managed }.policy do
        enable :read_orbit_instance_access
        enable :read_orbit_trial
      end

      desc "User can designate account beneficiaries: manager and successor"
      condition(:designated_account_beneficiaries_available, scope: :user) do
        ::Gitlab::Saas.feature_available?(:designated_account_beneficiaries) && !@user.enterprise_user?
      end

      rule { designated_account_beneficiaries_available }.enable :create_designated_account_beneficiaries

      rule { enterprise_user_disallowed_personal_snippets }.prevent :create_snippet

      desc "User can assign a default Duo group setting"
      condition(:default_duo_group_assignment_available) do
        can_assign_default_duo_group?
      end

      rule { default_duo_group_assignment_available }.enable :assign_default_duo_group

      desc "User can update a governing Orbit (Knowledge Graph) namespace setting"
      condition(:governing_knowledge_graph_namespace_update_available) do
        can_update_governing_knowledge_graph_namespace?
      end

      rule { governing_knowledge_graph_namespace_update_available }
        .enable :update_governing_knowledge_graph_namespace

      desc "Instance has read_dedicated_hosted_runner_usage feature available"
      condition(:dedicated_hosted_runner_usage_available) do
        ::Gitlab::Dedicated.feature_available?(:read_dedicated_hosted_runner_usage)
      end

      rule { dedicated_hosted_runner_usage_available & admin }.enable :read_dedicated_hosted_runner_usage
    end

    # Check whether a user is allowed to use Duo Chat powered by self-hosted models
    def duo_chat_self_hosted?
      ::Ai::FeatureSetting.find_by_feature(:duo_chat)&.self_hosted?
    end

    def dap_self_hosted?
      return true unless ::License.current&.offline_cloud_license?

      ::GitlabSubscriptions::AddOnPurchase.for_self_managed.for_self_hosted_dap.active.exists?
    end

    def custom_role_ability(user)
      strong_memoize_with(:custom_role_ability, user) do
        ::Authz::CustomAbility.new(user)
      end
    end

    def self_hosted_enabled_for_dedicated?
      ::Gitlab::Utils.to_boolean(ENV.fetch('ALLOW_DEDICATED_SELF_HOSTED_AIGW', false)) ||
        !::Gitlab::Dedicated.feature_available?(:restrict_self_hosted_ai_gateway)
    end

    def can_assign_default_duo_group?
      return false if ::Ai::AmazonQ.connected?

      return false unless user.user_preference.duo_default_namespace_candidates.exists?

      ::Gitlab::CurrentSettings.current_application_settings.duo_features_enabled
    end

    def can_update_governing_knowledge_graph_namespace?
      return false unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      return false unless ::Feature.enabled?(:knowledge_graph_billing, user)

      ::Analytics::KnowledgeGraph::GoverningNamespaceFinder.for(user).candidates.exists?
    end
  end
end
