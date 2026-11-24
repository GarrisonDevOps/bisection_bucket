# frozen_string_literal: true

module Sidebars
  module Groups
    module Menus
      class SecurityComplianceMenu < ::Sidebars::Menu
        include Gitlab::Utils::StrongMemoize
        include ::SecretsManagement::Concerns::ShowsNavBadge
        include ::Security::Concerns::ShowsNavIndicator

        override :configure_menu_items
        def configure_menu_items
          add_item(security_dashboard_menu_item)
          add_item(vulnerability_report_menu_item)
          add_item(security_inventory_menu_item)
          add_item(dependencies_menu_item)
          add_item(compliance_menu_item)
          add_item(credentials_menu_item)
          add_item(scan_policies_menu_item)
          add_item(policy_store_menu_item)
          add_item(dependency_firewall_menu_item)
          add_item(audit_events_menu_item)
          add_item(configuration_menu_item)
          add_item(secrets_manager_menu_item)

          true
        end

        override :link
        def link
          return group_security_discover_path(context.group) if renderable_items.empty?

          super
        end

        override :title
        def title
          renderable_items.any? ? _('Security and compliance') : _('Security')
        end

        override :sprite_icon
        def sprite_icon
          'shield'
        end

        override :render?
        def render?
          super || context.show_discover_group_security
        end

        override :active_routes
        def active_routes
          return {} if renderable_items.empty?

          { page: link }
        end

        override :serialize_as_menu_item_args
        def serialize_as_menu_item_args
          nil
        end

        private

        def security_dashboard_menu_item
          unless can_access_group_security_dashboard_and_vulnerability_report?
            return ::Sidebars::NilMenuItem.new(item_id: :security_dashboard)
          end

          ::Sidebars::MenuItem.new(
            title: _('Security dashboard'),
            link: group_security_dashboard_path(context.group),
            super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::SecureMenu,
            active_routes: { path: 'dashboard#show' },
            item_id: :security_dashboard,
            description: _('View security findings and trends'),
            library_icon: 'shield',
            tier: tier_for(:security_dashboard)
          )
        end

        def vulnerability_report_menu_item
          unless can_access_group_security_dashboard_and_vulnerability_report?
            return ::Sidebars::NilMenuItem.new(item_id: :vulnerability_report)
          end

          ::Sidebars::MenuItem.new(
            title: _('Vulnerability report'),
            link: group_security_vulnerabilities_path(context.group),
            super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::SecureMenu,
            active_routes: { path: 'vulnerabilities#index' },
            item_id: :vulnerability_report,
            description: _('Monitor and address security vulnerabilities'),
            library_icon: 'review-warning',
            tier: tier_for(:security_dashboard)
          )
        end

        def security_inventory_menu_item
          unless can_access_security_inventory_dashboard?
            return ::Sidebars::NilMenuItem.new(item_id: :security_inventory)
          end

          ::Sidebars::MenuItem.new(
            title: _('Security inventory'),
            link: group_security_inventory_path(context.group),
            super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::SecureMenu,
            active_routes: { path: 'inventory#show' },
            item_id: :security_inventory,
            badge: security_nav_indicator_badge(:inventory, context.group),
            description: _('Inventory of security assets'),
            library_icon: 'security-inventory',
            tier: tier_for(:security_inventory)
          )
        end

        def secrets_manager_menu_item
          unless group_level_secrets_manager_available?
            return ::Sidebars::NilMenuItem.new(item_id: :secrets_manager)
          end

          ::Sidebars::MenuItem.new(
            title: _('Secrets manager'),
            link: group_secrets_path(context.group),
            super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::SecureMenu,
            active_routes: { path: 'groups/secrets' },
            item_id: :secrets_manager,
            badge: secrets_manager_badge,
            description: _('Store and manage group secrets'),
            library_icon: 'secrets-manager',
            tier: :add_on
          )
        end

        def dependencies_menu_item
          unless read_group_level_dependencies_available?
            return ::Sidebars::NilMenuItem.new(item_id: :dependency_list)
          end

          ::Sidebars::MenuItem.new(
            title: _('Dependency list'),
            link: group_dependencies_path(context.group),
            super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::SecureMenu,
            active_routes: { path: 'dependencies#index' },
            item_id: :dependency_list,
            description: _('Track dependencies and known vulnerabilities'),
            library_icon: 'dependency-list',
            tier: tier_for(:security_dashboard)
          )
        end

        def compliance_menu_item
          unless group_level_compliance_dashboard_available?
            return ::Sidebars::NilMenuItem.new(item_id: :compliance)
          end

          ::Sidebars::MenuItem.new(
            title: _('Compliance center'),
            link: group_security_compliance_dashboard_path(context.group),
            super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::SecureMenu,
            active_routes: { path: 'compliance_dashboards#show' },
            item_id: :compliance,
            description: _('Monitor and enforce compliance'),
            library_icon: 'compliance',
            tier: tier_for(:group_level_compliance_dashboard)
          )
        end

        def group_level_compliance_dashboard_available?
          context.group.licensed_feature_available?(:group_level_compliance_dashboard) &&
            can?(context.current_user, :read_compliance_dashboard, context.group)
        end

        def group_level_secrets_manager_available?
          return false unless can?(context.current_user, :read_secret, context.group)
          return true if context.group.secrets_manager&.active?

          can_set_up_group_secrets_manager?
        end

        # The abilities the setup page's actions authorize; provisioning is a write, denied in read-only states.
        def can_set_up_group_secrets_manager?
          root = context.group.root_ancestor

          can?(context.current_user, :start_secrets_manager_trial, root) ||
            can?(context.current_user, :enable_secrets_manager_add_on, root) ||
            can?(context.current_user, :provision_secrets_manager, context.group)
        end

        def credentials_menu_item
          unless group_level_credentials_inventory_available?
            return ::Sidebars::NilMenuItem.new(item_id: :credentials)
          end

          ::Sidebars::MenuItem.new(
            title: _('Credentials'),
            link: group_security_credentials_path(context.group),
            super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::SecureMenu,
            active_routes: { path: 'credentials#index' },
            item_id: :credentials,
            description: _('Manage group credentials inventory'),
            library_icon: 'credentials',
            tier: tier_for(:credentials_inventory)
          )
        end

        def group_level_credentials_inventory_available?
          can?(context.current_user, :read_group_credentials_inventory, context.group)
        end

        def scan_policies_menu_item
          unless group_level_security_policies_available?
            return ::Sidebars::NilMenuItem.new(item_id: :scan_policies)
          end

          ::Sidebars::MenuItem.new(
            title: _('Policies'),
            link: group_security_policies_path(context.group),
            super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::SecureMenu,
            active_routes: { controller: ['groups/security/policies'] },
            item_id: :scan_policies,
            description: _('Set rules to protect your projects and data'),
            library_icon: 'policy',
            tier: tier_for(:security_orchestration_policies)
          )
        end

        def group_level_security_policies_available?
          can?(context.current_user, :read_security_orchestration_policies, context.group)
        end

        def policy_store_menu_item
          unless policy_store_available?
            return ::Sidebars::NilMenuItem.new(item_id: :policy_store)
          end

          ::Sidebars::MenuItem.new(
            title: _('Policy store'),
            link: group_security_policy_store_index_path(context.group),
            super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::SecureMenu,
            active_routes: { controller: ['groups/security/policy_store'] },
            item_id: :policy_store,
            description: _('Experimental store for security policies'),
            library_icon: 'policy',
            tier: tier_for(:security_orchestration_policies)
          )
        end

        def policy_store_available?
          context.group.policy_store_experiment_active? && group_level_security_policies_available?
        end

        def dependency_firewall_menu_item
          unless dependency_firewall_dashboard_available?
            return ::Sidebars::NilMenuItem.new(item_id: :dependency_firewall)
          end

          ::Sidebars::MenuItem.new(
            title: s_('DependencyFirewall|Dependency firewall'),
            link: group_security_dependency_firewall_path(context.group),
            super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::SecureMenu,
            active_routes: { controller: ['groups/security/dependency_firewall'] },
            item_id: :dependency_firewall
          )
        end

        def dependency_firewall_dashboard_available?
          ::Security::DependencyFirewall::Availability.enforced_for?(context.group) &&
            group_level_security_policies_available?
        end

        def audit_events_menu_item
          unless group_level_audit_events_available?
            return ::Sidebars::NilMenuItem.new(item_id: :audit_events)
          end

          ::Sidebars::MenuItem.new(
            title: _('Audit events'),
            link: group_audit_events_path(context.group),
            super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::SecureMenu,
            active_routes: { path: 'audit_events#index' },
            item_id: :audit_events,
            description: _('Review a record of changes and access events'),
            library_icon: 'audit-events',
            tier: tier_for(:audit_events)
          )
        end

        def configuration_menu_item
          unless can_access_group_security_configuration?
            return ::Sidebars::NilMenuItem.new(item_id: :configuration)
          end

          ::Sidebars::MenuItem.new(
            title: _('Security configuration'),
            link: group_security_configuration_path(context.group),
            super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::SecureMenu,
            active_routes: { controller: ['groups/security/configuration'] },
            item_id: :configuration,
            badge: security_nav_indicator_badge(:configuration, context.group.root_ancestor),
            description: _('Configure security scanning and settings'),
            library_icon: 'secrets-manager',
            tier: :ultimate
          )
        end

        def group_level_audit_events_available?
          context.group.licensed_feature_available?(:audit_events) &&
            can?(context.current_user, :read_audit_event, context.group)
        end

        def read_group_level_dependencies_available?
          context.group.licensed_feature_available?(:security_dashboard) &&
            can?(context.current_user, :read_dependency, context.group)
        end

        def can_access_group_security_dashboard_and_vulnerability_report?
          context.group.licensed_feature_available?(:security_dashboard) &&
            can?(context.current_user, :read_vulnerability, context.group)
        end

        def can_access_security_inventory_dashboard?
          can?(context.current_user, :read_security_inventory, context.group)
        end

        def can_access_group_security_attributes?
          can?(context.current_user, :admin_security_attributes, context.group.root_ancestor) &&
            context.group.licensed_feature_available?(:security_attributes)
        end

        def can_access_group_security_scan_profiles?
          can?(context.current_user, :read_security_scan_profiles, context.group.root_ancestor) &&
            context.group.licensed_feature_available?(:security_scan_profiles)
        end

        def can_access_group_security_configuration?
          can_access_group_security_attributes? || can_access_group_security_scan_profiles?
        end
      end
    end
  end
end
