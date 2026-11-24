# frozen_string_literal: true

module EE
  module Sidebars
    module Groups
      module Menus
        module SettingsMenu
          extend ::Gitlab::Utils::Override
          include ::GitlabSubscriptions::SubscriptionHelper
          include ::Groups::AnalyticsDashboardHelper
          include ::Nav::GitlabDuoSettingsPage
          include ::WorkItems::SettingsPermissions

          override :configure_menu_items
          def configure_menu_items
            super

            if can?(context.current_user, :read_webhook, context.group)
              insert_item_after(:integrations, webhooks_menu_item)
            end

            if can?(context.current_user, :admin_group, context.group)
              add_admin_group_settings_menu_items
            else
              add_limited_settings_menu_items
            end
          end

          private

          def add_admin_group_settings_menu_items
            insert_item_after(:service_accounts, roles_and_permissions_menu_item)
            insert_item_after(:access_tokens, group_work_items_menu_item)
            insert_item_after(:ci_cd, analytics_menu_item)
            insert_item_after(:packages_and_registries, secure_menu_item)
            insert_item_after(:usage_quotas, gitlab_duo_settings_menu_item)
            insert_item_after(:gitlab_duo_settings, gitlab_credits_dashboard_menu)
            insert_item_after(:gitlab_duo_settings, orbit_menu_item)
            add_item(ldap_sync_menu_item)
            add_item(saml_sso_menu_item)
            add_item(saml_group_links_menu_item)
            add_item(domain_verification_menu_item)
            add_item(billing_menu_item)
            add_item(reporting_menu_item)
            add_item(workspaces_menu_item)
          end

          def add_limited_settings_menu_items
            add_menu_item_for_abilities(general_menu_item,
              [:remove_group, :archive_group, :manage_merge_request_settings])
            add_menu_item_for_abilities(integrations_menu_item, :admin_integrations)
            add_menu_item_for_abilities(access_tokens_menu_item, :read_resource_access_tokens)
            add_item(group_work_items_menu_item)
            add_menu_item_for_abilities(repository_menu_item, [:admin_push_rules, :manage_deploy_tokens])
            add_menu_item_for_abilities(ci_cd_menu_item, [:admin_cicd_variables,
              :admin_protected_environments, :update_runners_setting])
            add_menu_item_for_abilities(billing_menu_item, :read_billing)
            add_menu_item_for_abilities(workspaces_menu_item, :read_namespace_cluster_agent_mapping)
          end

          def add_menu_item_for_abilities(menu_item, abilities)
            add_item(menu_item) if can_any?(context.current_user, Array(abilities), context.group)
          end

          def roles_and_permissions_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :roles_and_permissions) unless custom_roles_enabled?

            ::Sidebars::MenuItem.new(
              title: _('Roles and permissions'),
              link: group_settings_roles_and_permissions_path(context.group),
              active_routes: { controller: :roles_and_permissions },
              item_id: :roles_and_permissions,
              library_icon: 'settings'
            )
          end

          def custom_roles_enabled?
            context.group.root? &&
              can?(context.current_user, :view_member_roles, context.group) &&
              gitlab_com_subscription?
          end

          def ldap_sync_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :ldap_sync) unless ldap_sync_enabled?

            ::Sidebars::MenuItem.new(
              title: _('LDAP Synchronization'),
              link: group_ldap_group_links_path(context.group),
              active_routes: { path: 'ldap_group_links#index' },
              item_id: :ldap_sync,
              library_icon: 'settings'
            )
          end

          def ldap_sync_enabled?
            ::Gitlab::Auth::Ldap::Config.group_sync_enabled? &&
              can?(context.current_user, :read_ldap_group_link, context.group)
          end

          def saml_sso_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :saml_sso) unless saml_sso_enabled?

            ::Sidebars::MenuItem.new(
              title: _('SAML SSO'),
              link: group_saml_providers_path(context.group),
              active_routes: { path: %w[saml_providers#show saml_providers#update] },
              item_id: :saml_sso,
              library_icon: 'settings'
            )
          end

          def saml_sso_enabled?
            can?(context.current_user, :admin_group_saml, context.group)
          end

          def saml_group_links_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :saml_group_links) unless
              can?(context.current_user, :admin_saml_group_links, context.group)

            ::Sidebars::MenuItem.new(
              title: s_('GroupSAML|SAML Group Links'),
              link: group_saml_group_links_path(context.group),
              active_routes: { path: 'saml_group_links#index' },
              item_id: :saml_group_links,
              library_icon: 'settings'
            )
          end

          def domain_verification_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :domain_verification) unless domain_verification_available?

            ::Sidebars::MenuItem.new(
              title: _('Domain Verification'),
              link: group_settings_domain_verification_index_path(context.group),
              active_routes: { controller: :domain_verification },
              item_id: :domain_verification,
              library_icon: 'settings'
            )
          end

          def domain_verification_available?
            can?(context.current_user, :admin_group, context.group) && context.group.domain_verification_available?
          end

          def webhooks_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :webhooks) unless webhooks_enabled?

            ::Sidebars::MenuItem.new(
              title: _('Webhooks'),
              link: group_hooks_path(context.group),
              active_routes: { path: 'hooks#index' },
              item_id: :webhooks,
              library_icon: 'settings'
            )
          end

          def webhooks_enabled?
            context.group.licensed_feature_available?(:group_webhooks) ||
              context.show_promotions
          end

          def billing_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :billing) unless billing_enabled?

            ::Sidebars::MenuItem.new(
              title: _('Billing'),
              link: group_billings_path(context.group),
              active_routes: { controller: :billings },
              item_id: :billing,
              library_icon: 'settings'
            )
          end

          def billing_enabled?
            ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          end

          def reporting_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :reporting) unless
              context.group.unique_project_download_limit_enabled?

            ::Sidebars::MenuItem.new(
              title: s_('GroupSettings|Reporting'),
              link: group_settings_reporting_path(context.group),
              active_routes: { path: 'reporting#show' },
              item_id: :reporting,
              library_icon: 'settings'
            )
          end

          def workspaces_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :workspaces) unless workspaces_enabled?

            ::Sidebars::MenuItem.new(
              title: _('Workspaces'),
              link: group_settings_workspaces_path(context.group),
              active_routes: { path: 'groups/settings/remote_development/workspaces#show' },
              item_id: :workspaces_settings,
              library_icon: 'settings'
            )
          end

          def workspaces_enabled?
            can?(context.current_user, :access_workspaces_feature)
          end

          def analytics_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :analytics) unless analytics_available?

            ::Sidebars::MenuItem.new(
              title: _('Analytics'),
              link: group_settings_analytics_path(context.group),
              active_routes: { path: %w[analytics#show] },
              item_id: :analytics,
              library_icon: 'settings'
            )
          end

          def analytics_available?
            group_analytics_settings_available?(context.current_user, context.group)
          end

          def secure_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :secure) unless context.group.secure_settings_available?

            ::Sidebars::MenuItem.new(
              title: s_('GroupSettings|Secure'),
              link: group_settings_secure_path(context.group),
              active_routes: { path: 'secure#show' },
              item_id: :secure,
              library_icon: 'settings'
            )
          end

          def gitlab_duo_settings_menu_item
            unless show_gitlab_duo_settings_menu_item?(context.group)
              return ::Sidebars::NilMenuItem.new(item_id: :gitlab_duo_settings)
            end

            ::Sidebars::MenuItem.new(
              title: _('GitLab Duo'),
              link: group_settings_gitlab_duo_path(context.group),
              active_routes: {
                path: [
                  'gitlab_duo#show',
                  'configuration#index',
                  'seat_utilization#index'
                ]
              },
              item_id: :gitlab_duo_settings,
              library_icon: 'settings'
            )
          end

          def orbit_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :orbit) unless show_orbit_menu_item?

            ::Sidebars::MenuItem.new(
              title: s_('Orbit|GitLab Orbit'),
              link: group_settings_orbit_path(context.group),
              active_routes: { controller: 'groups/settings/orbit' },
              item_id: :orbit,
              library_icon: 'settings'
            )
          end

          def show_orbit_menu_item?
            can?(context.current_user, :read_orbit_setting, context.group)
          end

          def gitlab_credits_dashboard_menu
            unless gitlab_credits_dashboard_available?
              return ::Sidebars::NilMenuItem.new(item_id: :gitlab_credits_dashboard)
            end

            ::Sidebars::MenuItem.new(
              title: _('GitLab Credits'),
              link: group_settings_gitlab_credits_dashboard_index_path(context.group),
              active_routes: {
                path: [
                  'groups/settings/gitlab_credits_dashboard#index',
                  'groups/settings/gitlab_credits_dashboard/users#show'
                ]
              },
              item_id: :gitlab_credits_dashboard,
              library_icon: 'settings'
            )
          end

          def group_work_items_menu_item
            unless show_group_work_items_settings_menu_item?
              return ::Sidebars::NilMenuItem.new(item_id: :group_work_items_settings)
            end

            title = _('Work items')
            link = group_settings_work_items_path(context.group)

            ::Sidebars::MenuItem.new(
              title: title,
              link: link,
              active_routes: { controller: 'groups/settings/work_items', path: ['groups/settings/work_items#show'] },
              item_id: :group_work_items_settings,
              library_icon: 'settings'
            )
          end

          def show_group_work_items_settings_menu_item?
            can_access_work_item_settings?(context.group, context.current_user)
          end

          def gitlab_credits_dashboard_available?
            if ::Feature.enabled?(:hide_gitlab_credits_page, context.group) &&
                context.group.plan_name_for_upgrading == ::GitlabSubscriptions::SystemDefined::Plan::FREE
              return false
            end

            return false unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
            return false unless context.group.gitlab_credits_entitled?

            context.group.root?
          end

          override :packages_and_registries_controllers
          def packages_and_registries_controllers
            super + %i[virtual_registry_cleanup_policy]
          end
        end
      end
    end
  end
end
