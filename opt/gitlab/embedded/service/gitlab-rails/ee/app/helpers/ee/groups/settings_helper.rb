# frozen_string_literal: true

module EE
  module Groups
    module SettingsHelper
      include ::GitlabSubscriptions::UsageBillingHelper

      def unique_project_download_limit_settings_data
        settings = @group.namespace_settings || ::NamespaceSetting.new
        limit = settings.unique_project_download_limit
        interval = settings.unique_project_download_limit_interval_in_seconds
        allowlist = settings.unique_project_download_limit_allowlist
        alertlist = settings.unique_project_download_limit_alertlist
        auto_ban_users = settings.auto_ban_user_on_excessive_projects_download

        {
          group_full_path: @group.full_path,
          max_number_of_repository_downloads: limit,
          max_number_of_repository_downloads_within_time_period: interval,
          git_rate_limit_users_allowlist: allowlist,
          git_rate_limit_users_alertlist: alertlist,
          auto_ban_user_on_excessive_projects_download: auto_ban_users.to_s
        }
      end

      def show_group_ai_settings_general?
        ::GitlabSubscriptions::Duo.duo_settings_available?(@group.root_ancestor)
      end

      def show_group_ai_settings_page?
        @group.licensed_ai_features_available? && show_gitlab_duo_settings_app?(@group)
      end

      def show_virtual_registries_setting?(group)
        ::VirtualRegistries.any_registry_available_for_settings?(group, current_user)
      end

      def group_ai_general_settings_helper_data
        {
          on_general_settings_page: 'true',
          redirect_path: edit_group_path(@group)
        }.merge(group_ai_settings_helper_data)
      end

      def group_ai_configuration_settings_helper_data
        {
          on_general_settings_page: 'false',
          redirect_path: group_settings_gitlab_duo_path(@group)
        }.merge(group_ai_settings_helper_data)
      end

      def group_ai_settings_helper_data
        duo_cascading_settings_data.merge(duo_feature_settings_data)
      end

      def group_amazon_q_settings_view_model_data
        {
          group_id: @group.id.to_s,
          init_availability: @group.namespace_settings.duo_availability.to_s,
          init_auto_review_enabled: @group.amazon_q_integration&.auto_review_enabled.present?,
          are_duo_settings_locked: @group.namespace_settings.duo_features_enabled_locked?,
          duo_availability_admin_locked: @group.namespace_settings.admin_locked_duo_features_enabled?,
          duo_availability_cascading_settings: cascading_namespace_settings_popover_raw_data(:duo_features_enabled, @group, method(:edit_group_path))
        }
      end

      def group_amazon_q_settings_view_model_json
        ::Gitlab::Json.generate(group_amazon_q_settings_view_model_data.deep_transform_keys { |k| k.to_s.camelize(:lower) })
      end

      def seat_control_disabled_help_text
        _("Restricted access and user cap cannot be turned on. The group or one of its subgroups or projects is shared externally.")
      end

      def usage_billing_dashboard_data(group, plans_data)
        premium_plan = find_plan(plans_data, ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM)

        {
          user_usage_path: group_settings_gitlab_credits_dashboard_user_path(group, '__USERNAME__'),
          namespace_path: group.full_path,
          subscription_start_date: group.gitlab_subscription&.start_date&.iso8601,
          upgrade_button_path: plan_purchase_url(group, premium_plan),
          is_free: free_namespace?(group).to_s,
          purchase_credits_path: subscription_portal_gitlab_com_purchase_credits_url(group.id),
          credits_generalization_ui: ::Feature.enabled?(:credits_generalization_ui, group).to_s
        }
      end

      def seat_control_warning?(group)
        !!group.saml_provider&.enabled?
      end

      def seat_control_saml_scim_warning
        saml_link = link_to('', help_page_path('user/group/saml_sso/_index.md'))
        scim_link = link_to('', help_page_path('user/group/saml_sso/scim_setup.md'))

        message = safe_format(
          _(
            '%{saml_link_start}SAML%{saml_link_end}/%{scim_link_start}SCIM%{scim_link_end} provisioning is active. ' \
              'With restricted access turned on and if no seats are available, new users provisioned through SAML/SCIM are ' \
              'assigned the non-billable Minimal Access role.'
          ),
          tag_pair(saml_link, :saml_link_start, :saml_link_end),
          tag_pair(scim_link, :scim_link_start, :scim_link_end)
        )

        tag.div(class: 'gl-mt-3') do
          concat(sprite_icon('warning', size: 16, css_class: 'gl-mr-2 gl-text-orange-500'))
          concat(message)
        end
      end

      # Data for the AI Governance section on the group Secure settings page.
      #
      # @return [Hash]
      def ai_governance_settings_data
        {
          ai_governance_enabled: @group.ai_governance_enabled.to_s,
          lock_ai_governance_enabled: @group.lock_ai_governance_enabled.to_s,
          ai_governance_cascading_settings: cascading_popover_data(:ai_governance_enabled),
          ai_audit_events_storage_enabled: @group.namespace_settings.ai_audit_events_storage_enabled.to_s,
          lock_ai_audit_events_storage_enabled: @group.lock_ai_audit_events_storage_enabled.to_s,
          ai_audit_events_storage_cascading_settings: cascading_popover_data(:ai_audit_events_storage_enabled),
          update_path: ai_governance_group_settings_secure_path(@group)
        }
      end

      private

      def duo_cascading_settings_data
        data = {
          duo_availability_cascading_settings: cascading_popover_data(:duo_features_enabled),
          duo_remote_flows_cascading_settings: cascading_popover_data(:duo_remote_flows_enabled),
          duo_foundational_flows_cascading_settings: cascading_popover_data(:duo_foundational_flows_enabled),
          duo_scheduled_triggers_cascading_settings: cascading_popover_data(:duo_scheduled_triggers_enabled),
          duo_custom_agents_cascading_settings: cascading_popover_data(:duo_custom_agents_enabled),
          duo_custom_flows_cascading_settings: cascading_popover_data(:duo_custom_flows_enabled),
          duo_external_agents_cascading_settings: cascading_popover_data(:duo_external_agents_enabled),
          tool_approval_for_session_cascading_settings: cascading_popover_data(:tool_approval_for_session_enabled),
          ai_audit_events_storage_cascading_settings: cascading_popover_data(:ai_audit_events_storage_enabled)
        }

        if flows_settings.duo_auto_mode_enabled?
          data[:duo_auto_mode_cascading_settings] = cascading_popover_data(:duo_auto_mode_enabled)
        end

        data
      end

      def flows_settings
        @flows_settings ||= ::Ai::DuoSettings::FlowsSettingsSerializer.new(
          @group, current_user: current_user, flows: ::Ai::DuoSettings::FoundationalFlowsPresenter.new(@group)
        )
      end

      def duo_feature_settings_data
        {
          duo_availability: @group.namespace_settings.duo_availability.to_s,
          are_duo_settings_locked: @group.namespace_settings.duo_features_enabled_locked?.to_s,
          duo_availability_admin_locked: @group.namespace_settings.admin_locked_duo_features_enabled?.to_s,
          experiment_features_enabled: @group.namespace_settings.experiment_features_enabled.to_s,
          duo_core_features_enabled: @group.namespace_settings.duo_core_features_enabled.to_s,
          prompt_cache_enabled: @group.namespace_settings.model_prompt_cache_enabled.to_s,
          are_experiment_settings_allowed: (@group.experiment_settings_allowed? && gitlab_com_subscription?).to_s,
          are_prompt_cache_settings_allowed: (@group.prompt_cache_settings_allowed? && gitlab_com_subscription?).to_s,
          update_id: @group.id,
          root_namespace_id: @group.root_ancestor.id,
          is_saas: saas?.to_s,
          group_full_path: @group.full_path,
          readiness_card_enabled: duo_group_readiness_card_enabled?.to_s
        }.merge(
          duo_workflow_settings_data,
          ai_access_level_settings_data,
          flows_settings.settings,
          foundational_agents_data,
          namespace_access_rules_data,
          duo_readiness_settings_data
        )
      end

      def duo_workflow_settings_data
        {
          duo_agent_platform_enabled: @group.duo_agent_platform_enabled.to_s,
          duo_workflow_available: (@group.root? && Ability.allowed?(current_user, :admin_duo_workflow, @group)).to_s,
          duo_workflow_mcp_available: (@group.root? && Ability.allowed?(current_user, :admin_duo_workflow, @group) && @group.licensed_feature_available?(:ai_catalog)).to_s,
          duo_workflow_mcp_enabled: @group.duo_workflow_mcp_enabled.to_s,
          ai_usage_data_collection_available: (@group.root? && gitlab_com_subscription?).to_s,
          ai_usage_data_collection_enabled: @group.ai_usage_data_collection_enabled.to_s,
          ai_catalog_restricted_to_group_hierarchy: @group.ai_catalog_restricted_to_group_hierarchy.to_s,
          ai_catalog_restricted_to_group_hierarchy_available: @group.root?.to_s,
          ai_audit_events_storage_enabled: @group.namespace_settings.ai_audit_events_storage_enabled.to_s,
          web_search_enabled: @group.web_search_enabled.to_s,
          # Unlike prompt injection below, this omits the dap_web_search flag check:
          # the frontend owns that gate, so the flag is evaluated in exactly one place.
          # Off GitLab.com the instance setting decides, so the group value is never read.
          web_search_available: (saas? && root_group_duo_workflow_admin?).to_s,
          duo_workflow_file_attachments_enabled: @group.duo_workflow_file_attachments_enabled.to_s,
          # Self-managed and Dedicated use the instance setting instead.
          duo_workflow_file_attachments_available: (root_group_duo_workflow_admin? && gitlab_com_subscription?).to_s,
          prompt_injection_protection_level: @group.prompt_injection_protection_level.to_s,
          prompt_injection_protection_available: (::Feature.enabled?(:ai_prompt_scanning, current_user) && Ability.allowed?(current_user, :admin_duo_workflow, @group)).to_s,
          show_duo_agent_platform_enablement_setting: show_duo_agent_platform_enablement_setting?.to_s
        }.merge(sandbox_settings_data)
      end

      def sandbox_settings_data
        {
          include_recommended_allowed: @group.ai_settings.include_recommended_allowed.to_s,
          allow_all_unix_sockets: @group.ai_settings.allow_all_unix_sockets.to_s,
          allow_project_extension: @group.ai_settings.allow_project_extension.to_s,
          enforce_on_local_clients: @group.ai_settings.enforce_on_local_clients.to_s,
          require_sandbox: @group.ai_settings.require_sandbox.to_s,
          # Only read from the top-level group on GitLab.com; elsewhere the instance setting applies.
          require_sandbox_available: (saas? && @group.root?).to_s
        }
      end

      def root_group_duo_workflow_admin?
        @group.root? && Ability.allowed?(current_user, :admin_duo_workflow, @group)
      end

      def ai_access_level_settings_data
        {
          ai_minimum_access_level_to_execute: @group.ai_minimum_access_level_execute_with_fallback,
          ai_minimum_access_level_to_execute_async: @group.ai_minimum_access_level_execute_async_with_fallback,
          ai_settings_minimum_access_level_manage: @group.ai_minimum_access_level_manage,
          ai_settings_minimum_access_level_enable_on_projects: @group.ai_minimum_access_level_enable_on_projects
        }
      end

      def foundational_agents_data
        agents = ::Ai::DuoSettings::FoundationalAgentsPresenter.new(@group, current_user: current_user)

        {
          foundational_agents_default_enabled: @group.foundational_agents_default_enabled.to_s,
          foundational_agents_statuses: ::Gitlab::Json.generate(agents.listed_statuses),
          show_foundational_agents_availability: show_foundational_agents_availability?.to_s,
          show_foundational_agents_per_agent_availability: show_foundational_agents_per_agent_availability?.to_s
        }
      end

      def cascading_popover_data(setting_key)
        cascading_namespace_settings_popover_data(setting_key, @group, method(:edit_group_path))[:popover_data]
      end

      def namespace_access_rules_data
        {
          namespace_access_rules: ::Gitlab::Json.dump(namespace_access_rules),
          new_group_path: new_group_path(parent_id: @group.id, anchor: 'create-group-pane')
        }
      end

      def namespace_access_rules
        rules = ::Ai::NamespaceFeatureAccessRule.by_root_namespace_group_by_through_namespace(@group)

        Ai::FeatureAccessRuleTransformer.transform(rules)
      end

      def duo_readiness_settings_data
        return {} unless duo_group_readiness_card_enabled?

        {
          duo_agent_platform_owner_enabled: ::Ai::DuoWorkflow.duo_agent_platform_available?(@group).to_s,
          duo_agent_platform_owner_settings_path: duo_agent_platform_owner_settings_path,
          foundational_agents_owner_enabled: foundational_agents_owner_enabled.to_s,
          root_ancestor_name: @group.root_ancestor.name,
          duo_workflow_mcp_root_enabled: @group.root_ancestor.duo_workflow_mcp_enabled.to_s,
          duo_orbit: ::Gitlab::Json.dump(group_orbit_data)
        }.merge(group_mcp_servers_data)
      end

      def group_orbit_data
        return {} unless ::Analytics::KnowledgeGraph.enabled_for?(current_user)

        root_ancestor = @group.root_ancestor
        return {} unless ::Analytics::Orbit::Billing.account_for(root_ancestor).eligible?

        data = {
          enabled: root_ancestor.knowledge_graph_enabled_namespace.present?,
          can_enable: @group.root? && Ability.allowed?(current_user, :update_knowledge_graph_setting, root_ancestor),
          can_start_trial: @group.root? && Ability.allowed?(current_user, :start_orbit_trial, root_ancestor),
          root_group_path: root_ancestor.full_path,
          graph_path: dashboard_orbit_path,
          settings_path: group_settings_orbit_path(root_ancestor)
        }
        return data if @group.root?

        data.merge(cascading_settings: {
          locked_by_ancestor: true,
          locked_by_application_setting: false,
          ancestor_namespace: { full_name: root_ancestor.full_name, path: edit_group_path(root_ancestor) }
        })
      end

      # The MCP row hides when the viewer cannot use MCP servers at all. Without the path
      # it skips its query and shows a neutral line: the policy redacts the field when the
      # viewer cannot read it, and a subgroup has nothing to list until inheritance is on.
      # Servers are managed on the top-level group, so that is where the row links.
      def group_mcp_servers_data
        return { mcp_servers_available: 'false' } unless ::Ai::Catalog.mcp_servers_available?(current_user)

        data = { mcp_servers_available: 'true' }
        return data unless Ability.allowed?(current_user, :read_ai_catalog_mcp_server, @group)
        return data unless ::Ai::DuoWorkflow::GroupReadiness.new(@group, current_user).lists_mcp_servers?

        data.merge(group_mcp_servers_path: group_automate_mcp_servers_path(@group.root_ancestor))
      end

      def duo_group_readiness_card_enabled?
        ::Ai::DuoSettings::FoundationalFlowsPresenter.new(@group).readiness_card_enabled?
      end

      def duo_agent_platform_owner_settings_path
        return if show_duo_agent_platform_enablement_setting?

        if saas?
          root_group_duo_settings_path
        elsif current_user.can_admin_all_resources?
          admin_gitlab_duo_configuration_index_path
        end
      end

      def root_group_duo_settings_path
        root_ancestor = @group.root_ancestor
        return unless Ability.allowed?(current_user, :admin_group, root_ancestor)

        root_ancestor.duo_settings_path
      end

      def foundational_agents_owner_enabled
        return @group.root_ancestor.foundational_agents_default_enabled if saas?

        @group.organization.foundational_agents_default_enabled
      end

      def show_foundational_agents_availability?
        saas? && @group.root?
      end

      def show_duo_agent_platform_enablement_setting?
        saas? && @group.root?
      end

      def show_foundational_agents_per_agent_availability?
        saas? && @group.root?
      end

      def saas?
        ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      end
    end
  end
end
