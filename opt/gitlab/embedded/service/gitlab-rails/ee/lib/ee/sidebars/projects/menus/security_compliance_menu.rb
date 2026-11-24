# frozen_string_literal: true

module EE
  module Sidebars
    module Projects
      module Menus
        module SecurityComplianceMenu
          extend ::Gitlab::Utils::Override
          include ::SecretsManagement::Concerns::ShowsNavBadge
          include ::Security::Concerns::ShowsNavIndicator

          override :configure_menu_items
          def configure_menu_items
            return false unless can_access_some_page?

            add_item(discover_project_security_menu_item)
            add_item(security_dashboard_menu_item)
            add_item(vulnerability_report_menu_item)
            add_item(on_demand_scans_menu_item)
            add_item(dependencies_menu_item)
            add_item(compliance_menu_item)
            add_item(scan_policies_menu_item)
            add_item(policy_store_menu_item)
            add_item(dependency_firewall_menu_item)
            add_item(audit_events_menu_item)
            add_item(configuration_menu_item)
            add_item(secrets_manager_menu_item)

            true
          end

          private

          def can_access_some_page?
            context.project.feature_available?(:security_and_compliance, context.current_user)
          end

          def can_access_security_dashboard?
            can?(context.current_user, :access_security_and_compliance, context.project) &&
              can?(context.current_user, :read_project_security_dashboard, context.project)
          end

          def can_access_configuration?
            can?(context.current_user, :access_security_and_compliance, context.project) &&
              can?(context.current_user, :read_security_configuration, context.project)
          end

          def can_access_license?
            can?(context.current_user, :access_security_and_compliance, context.project) &&
              can?(context.current_user, :read_licenses, context.project)
          end

          def can_access_dependencies?
            can?(context.current_user, :access_security_and_compliance, context.project) &&
              can?(context.current_user, :read_dependency, context.project)
          end

          override :configuration_menu_item_badge
          def configuration_menu_item_badge
            super || security_nav_indicator_badge(:configuration, context.project)
          end

          override :configuration_menu_item_paths
          def configuration_menu_item_paths
            super + %w[
              projects/security/sast_configuration#show
              projects/security/api_fuzzing_configuration#show
              projects/security/dast_configuration#show
              projects/security/dast_profiles#show
              projects/security/dast_site_profiles#new
              projects/security/dast_site_profiles#edit
              projects/security/dast_scanner_profiles#new
              projects/security/dast_scanner_profiles#edit
              projects/security/corpus_management#show
              projects/security/secret_detection_configuration#show
            ]
          end

          override :render_configuration_menu_item?
          def render_configuration_menu_item?
            super || can_access_configuration?
          end

          def discover_project_security_menu_item
            unless context.show_discover_project_security
              return ::Sidebars::NilMenuItem.new(item_id: :discover_project_security)
            end

            ::Sidebars::MenuItem.new(
              title: _('Security capabilities'),
              link: project_security_discover_path(context.project),
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::SecureMenu,
              active_routes: { path: 'projects/security/discover#show' },
              item_id: :discover_project_security,
              description: _('Explore security and compliance features'),
              library_icon: 'shield'
            )
          end

          def security_dashboard_menu_item
            unless can_access_security_dashboard?
              return ::Sidebars::NilMenuItem.new(item_id: :dashboard)
            end

            ::Sidebars::MenuItem.new(
              title: _('Security dashboard'),
              link: project_security_dashboard_index_path(context.project),
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::SecureMenu,
              active_routes: { path: 'projects/security/dashboard#index' },
              item_id: :dashboard,
              description: _('View security findings and trends'),
              library_icon: 'shield',
              tier: tier_for(:security_dashboard)
            )
          end

          def vulnerability_report_menu_item
            unless can?(context.current_user, :read_security_resource, context.project)
              return ::Sidebars::NilMenuItem.new(item_id: :vulnerability_report)
            end

            ::Sidebars::MenuItem.new(
              title: _('Vulnerability report'),
              link: project_security_vulnerability_report_index_path(context.project),
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::SecureMenu,
              active_routes: {
                path: %w[
                  projects/security/vulnerability_report#index
                  projects/security/vulnerabilities#show
                  projects/security/vulnerabilities#new
                ]
              },
              item_id: :vulnerability_report,
              description: _('Monitor and address security vulnerabilities'),
              library_icon: 'review-warning',
              tier: tier_for(:security_dashboard)
            )
          end

          def on_demand_scans_menu_item
            unless context.project.on_demand_dast_available?
              return ::Sidebars::NilMenuItem.new(item_id: :on_demand_scans)
            end

            unless can?(context.current_user, :read_on_demand_dast_scan, context.project)
              return ::Sidebars::NilMenuItem.new(item_id: :on_demand_scans)
            end

            link = project_on_demand_scans_path(context.project)

            ::Sidebars::MenuItem.new(
              title: s_('OnDemandScans|On-demand scans'),
              link: link,
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::SecureMenu,
              item_id: :on_demand_scans,
              active_routes: { path: %w[
                projects/on_demand_scans#index
                projects/on_demand_scans#new
                projects/on_demand_scans#edit
              ] },
              description: _('Scan any branch or environment on demand'),
              library_icon: 'on-demand-scan',
              tier: tier_for(:security_on_demand_scans)
            )
          end

          def dependencies_menu_item
            unless can_access_dependencies?
              return ::Sidebars::NilMenuItem.new(item_id: :dependency_list)
            end

            ::Sidebars::MenuItem.new(
              title: _('Dependency list'),
              link: project_dependencies_path(context.project),
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::SecureMenu,
              active_routes: { path: 'projects/dependencies#index' },
              item_id: :dependency_list,
              description: _('Track dependencies and known vulnerabilities'),
              library_icon: 'dependency-list',
              tier: tier_for(:dependency_scanning)
            )
          end

          def secrets_manager_menu_item
            unless project_level_secrets_manager_available?
              return ::Sidebars::NilMenuItem.new(item_id: :secrets_manager)
            end

            ::Sidebars::MenuItem.new(
              title: _('Secrets manager'),
              link: project_secrets_path(context.project),
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::SecureMenu,
              active_routes: { path: 'projects/secrets' },
              item_id: :secrets_manager,
              badge: secrets_manager_badge,
              description: _('Store and manage project secrets'),
              library_icon: 'secrets-manager',
              tier: :add_on
            )
          end

          def project_level_secrets_manager_available?
            return false unless can?(context.current_user, :read_project_secrets, context.project)
            return true if context.project.secrets_manager&.active?

            can_set_up_project_secrets_manager?
          end

          # The abilities the setup page's actions authorize; provisioning is a write, denied in read-only states.
          def can_set_up_project_secrets_manager?
            root = context.project.root_ancestor

            can?(context.current_user, :start_secrets_manager_trial, root) ||
              can?(context.current_user, :enable_secrets_manager_add_on, root) ||
              can?(context.current_user, :provision_secrets_manager, context.project)
          end

          def scan_policies_menu_item
            unless can?(context.current_user, :read_security_orchestration_policies, context.project)
              return ::Sidebars::NilMenuItem.new(item_id: :scan_policies)
            end

            ::Sidebars::MenuItem.new(
              title: _('Policies'),
              link: project_security_policies_path(context.project),
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::SecureMenu,
              active_routes: { controller: ['projects/security/policies'] },
              item_id: :scan_policies,
              description: _('Set rules to protect your projects and data'),
              library_icon: 'policy',
              tier: tier_for(:security_orchestration_policies)
            )
          end

          def policy_store_menu_item
            unless policy_store_available?
              return ::Sidebars::NilMenuItem.new(item_id: :policy_store)
            end

            ::Sidebars::MenuItem.new(
              title: _('Policy store'),
              link: project_security_policy_store_index_path(context.project),
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::SecureMenu,
              active_routes: { controller: ['projects/security/policy_store'] },
              item_id: :policy_store,
              description: _('View security policies that apply to this project'),
              library_icon: 'policy',
              tier: tier_for(:security_orchestration_policies)
            )
          end

          def policy_store_available?
            context.project.policy_store_experiment_active? &&
              can?(context.current_user, :read_govern_policy, context.project)
          end

          def dependency_firewall_menu_item
            unless dependency_firewall_dashboard_available?
              return ::Sidebars::NilMenuItem.new(item_id: :dependency_firewall)
            end

            ::Sidebars::MenuItem.new(
              title: s_('DependencyFirewall|Dependency firewall'),
              link: project_security_dependency_firewall_path(context.project),
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::SecureMenu,
              active_routes: { controller: ['projects/security/dependency_firewall'] },
              item_id: :dependency_firewall
            )
          end

          def dependency_firewall_dashboard_available?
            ::Security::DependencyFirewall::Availability.enforced_for?(context.project) &&
              can?(context.current_user, :read_security_orchestration_policies, context.project)
          end

          def compliance_menu_item
            unless project_level_compliance_dashboard_available?
              return ::Sidebars::NilMenuItem.new(item_id: :compliance)
            end

            ::Sidebars::MenuItem.new(
              title: _('Compliance center'),
              link: project_security_compliance_dashboard_path(context.project),
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::SecureMenu,
              active_routes: { path: 'compliance_dashboards#show' },
              item_id: :compliance,
              description: _('Monitor and enforce compliance'),
              library_icon: 'compliance',
              tier: tier_for(:project_level_compliance_dashboard)
            )
          end

          def audit_events_menu_item
            unless show_audit_events?
              return ::Sidebars::NilMenuItem.new(item_id: :audit_events)
            end

            ::Sidebars::MenuItem.new(
              title: _('Audit events'),
              link: project_audit_events_path(context.project),
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::SecureMenu,
              active_routes: { controller: :audit_events },
              item_id: :audit_events,
              description: _('Review a record of changes and access events'),
              library_icon: 'audit-events',
              tier: tier_for(:audit_events)
            )
          end

          def show_audit_events?
            can?(context.current_user, :read_audit_event, context.project) &&
              (context.project.licensed_feature_available?(:audit_events) || context.show_promotions)
          end

          def project_level_compliance_dashboard_available?
            can?(context.current_user, :read_compliance_dashboard, context.project)
          end
        end
      end
    end
  end
end
