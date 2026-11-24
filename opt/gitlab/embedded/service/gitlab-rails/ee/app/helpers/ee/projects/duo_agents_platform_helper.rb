# frozen_string_literal: true

module EE
  module Projects
    module DuoAgentsPlatformHelper
      def duo_agents_platform_data(project)
        root_group_id = project.personal? ? nil : project.root_namespace.id

        {
          agents_platform_base_route: project_automate_path(project),
          root_group_id: root_group_id,
          project_id: project.id,
          project_path: project.full_path,
          explore_ai_catalog_agents_path: explore_ai_catalog_agents_path,
          explore_ai_catalog_flows_path: explore_ai_catalog_flows_path,
          explore_ai_catalog_skills_path: explore_ai_catalog_skills_path,
          ai_impact_dashboard_enabled: ai_impact_dashboard_enabled?.to_s,
          credits_available: credits_available?(project).to_s,
          usage_billing_forbidden: usage_billing_forbidden?(project).to_s,
          instance_beta_features_enabled: instance_beta_features_enabled?.to_s,
          duo_scheduled_triggers_enabled: project.duo_scheduled_triggers_enabled.to_s,
          duo_scheduled_triggers_settings_path: scheduled_triggers_settings_path_for(project),

          ai_impact_dashboard_path: if ai_impact_dashboard_enabled?
                                      project_analytics_dashboards_path(project,
                                        vueroute: 'duo_and_sdlc_trends')
                                    end
        }.merge(duo_catalog_settings(project.root_ancestor))
          .merge(duo_agents_empty_state_data(project))
          .merge(trigger_schedule_data)
      end

      def duo_agents_group_data(group)
        {
          agents_platform_base_route: group_automate_path(group),
          group_id: group.id,
          group_path: group.full_path,
          group_name: group.full_name,
          explore_ai_catalog_agents_path: explore_ai_catalog_agents_path,
          explore_ai_catalog_flows_path: explore_ai_catalog_flows_path,
          ai_impact_dashboard_enabled: ai_impact_dashboard_enabled?.to_s,
          credits_available: credits_available?(group).to_s,
          usage_billing_forbidden: usage_billing_forbidden?(group).to_s,
          instance_beta_features_enabled: instance_beta_features_enabled?.to_s,
          duo_scheduled_triggers_enabled: group.duo_scheduled_triggers_enabled.to_s,

          ai_impact_dashboard_path: if ai_impact_dashboard_enabled?
                                      group_analytics_dashboards_path(group,
                                        vueroute: 'duo_and_sdlc_trends')
                                    end
        }.merge(duo_catalog_settings(group.root_ancestor))
          .merge(duo_agents_empty_state_data(group))
      end

      def dap_identity_verification_required?(container)
        return false unless current_user

        current_user.dap_identity_verification_required?(container)
      end

      def duo_agents_platform_identity_verification_data(container)
        {
          identity_verification_required: dap_identity_verification_required?(container).to_s,
          identity_verification_path: identity_verification_path
        }
      end

      private

      def duo_agents_empty_state_data(container)
        namespace = credits_billing_namespace(container)

        {
          on_free_plan: on_free_plan?(namespace).to_s,
          can_purchase_credits: can_purchase_credits?(namespace).to_s,
          buy_credits_path: buy_credits_path_for(namespace),
          learn_about_credits_path: help_page_url('subscriptions/gitlab_credits.md',
            anchor: 'buy-gitlab-credits')
        }
      end

      def credits_billing_namespace(container)
        current_user&.governing_namespace(container)
      end

      def on_free_plan?(namespace)
        strong_memoize_with(:on_free_plan, namespace) do
          next false unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          next false unless namespace

          namespace.free_plan?
        end
      end

      def can_purchase_credits?(namespace)
        return false unless on_free_plan?(namespace)
        return false unless namespace.is_a?(Group)

        can?(current_user, :edit_billing, namespace)
      end

      def buy_credits_path_for(namespace)
        return unless can_purchase_credits?(namespace)

        ::Gitlab::Routing.url_helpers.subscription_portal_gitlab_com_purchase_credits_url(namespace.id)
      end

      def trigger_schedule_data
        {
          timezone_data: timezone_data_with_unique_identifiers.to_json,
          user_timezone: current_user&.timezone
        }
      end

      def duo_catalog_settings(root_ancestor)
        {
          duo_beta_features_enabled: root_ancestor.duo_beta_flows_enabled?.to_s,
          duo_custom_agents_enabled: root_ancestor.duo_custom_agents_enabled.to_s,
          duo_custom_flows_enabled: root_ancestor.duo_custom_flows_enabled.to_s,
          duo_external_agents_enabled: root_ancestor.duo_external_agents_enabled.to_s,
          duo_settings_path: duo_settings_path_for(root_ancestor),
          duo_settings_root_ancestor_name: duo_settings_root_ancestor_name(root_ancestor)
        }
      end

      def scheduled_triggers_settings_path_for(project)
        return if project.project_setting.duo_scheduled_triggers_enabled_locked?
        return unless can?(current_user, :update_duo_setting, project)

        edit_project_path(project, anchor: 'js-gitlab-duo-settings')
      end

      def duo_settings_path_for(root_ancestor)
        return unless root_ancestor.is_a?(Group)
        return unless Ability.allowed?(current_user, :admin_group, root_ancestor) # rubocop:disable Gitlab/Authz/PermissionCheck -- no granular permission for group settings yet

        root_ancestor.duo_settings_path
      end

      def duo_settings_root_ancestor_name(root_ancestor)
        root_ancestor.name
      end

      def ai_impact_dashboard_enabled?
        ProductAnalyticsHelpers.ai_impact_dashboard_globally_available?
      end

      def instance_beta_features_enabled?
        ::Ai::Catalog.user_can_access_experimental_and_beta_features?(current_user)
      end

      def credits_available?(container)
        duo_chat_for(container).credits_available?
      end

      def usage_billing_forbidden?(container)
        duo_chat_for(container).usage_billing_forbidden?
      end

      def duo_chat_for(container)
        strong_memoize_with(:duo_chat_for, container) do
          ::Gitlab::Llm::DuoChat.new(user: current_user, container: container)
        end
      end
    end
  end
end
