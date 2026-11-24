# frozen_string_literal: true

module EE
  module Sidebars
    module Admin
      module Menus
        module AdminSettingsMenu
          include ::GitlabSubscriptions::SubscriptionHelper
          include ::WorkItems::SettingsPermissions
          extend ::Gitlab::Utils::Override

          override :configure_menu_items
          def configure_menu_items
            return false unless super

            insert_item_after(:service_accounts, roles_and_permissions_menu_item)
            insert_item_after(:admin_reporting, templates_menu_item)
            insert_item_after(:admin_ci_cd, security_and_compliance_menu_item)
            insert_item_after(:admin_preferences, usage_quotas_menu_item)

            if work_item_settings_available_for_self_managed?
              insert_item_after(:admin_security_and_compliance, work_item_settings_menu_item)
            end

            true
          end

          private

          def work_item_settings_menu_item
            ::Sidebars::MenuItem.new(
              title: _('Work items'),
              link: work_item_admin_application_settings_path,
              active_routes: { path: 'admin/application_settings#work_item' },
              item_id: :work_item_settings,
              container_html_options: { 'data-testid': 'admin-work-item-settings' }
            )
          end

          def roles_and_permissions_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :roles_and_permissions) unless roles_and_permissions_available?

            ::Sidebars::MenuItem.new(
              title: _('Roles and permissions'),
              link: admin_application_settings_roles_and_permissions_path,
              active_routes: { controller: :roles_and_permissions },
              item_id: :roles_and_permissions
            )
          end

          def roles_and_permissions_available?
            can?(current_user, :view_member_roles)
          end

          override :service_accounts_available?
          def service_accounts_available?
            super && !gitlab_com_subscription?
          end

          def templates_menu_item
            unless ::License.feature_available?(:custom_file_templates)
              return ::Sidebars::NilMenuItem.new(item_id: :admin_templates)
            end

            ::Sidebars::MenuItem.new(
              title: _('Templates'),
              link: templates_admin_application_settings_path,
              active_routes: { path: 'admin/application_settings#templates' },
              item_id: :admin_templates,
              container_html_options: { testid: 'admin-settings-templates-link' }
            )
          end

          def security_and_compliance_menu_item
            unless ::License.feature_available?(:license_scanning)
              return ::Sidebars::NilMenuItem.new(item_id: :admin_security_and_compliance)
            end

            ::Sidebars::MenuItem.new(
              title: _('Security and compliance'),
              link: security_and_compliance_admin_application_settings_path,
              active_routes: { path: 'admin/application_settings#security_and_compliance' },
              item_id: :admin_security_and_compliance,
              container_html_options: { testid: 'admin-security-and-compliance-link' }
            )
          end

          def usage_quotas_menu_item
            return unless dedicated?

            ::Sidebars::MenuItem.new(
              title: _('Usage quotas'),
              link: usage_quotas_admin_application_settings_path,
              active_routes: { path: 'admin/application_settings#usage_quotas' },
              item_id: :admin_usage_quotas,
              container_html_options: { 'data-testid': 'admin-settings-usage-quotas-link' }
            )
          end

          def dedicated?
            ::Gitlab::Dedicated.feature_available?(:usage_quotas_admin_menu_on_dedicated)
          end
        end
      end
    end
  end
end
