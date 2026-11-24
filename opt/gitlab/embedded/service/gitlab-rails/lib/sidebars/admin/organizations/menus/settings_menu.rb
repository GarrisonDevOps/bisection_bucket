# frozen_string_literal: true

module Sidebars
  module Admin
    module Organizations
      module Menus
        class SettingsMenu < ::Sidebars::Admin::BaseMenu
          override :configure_menu_items
          def configure_menu_items
            add_item(general_menu_item)
            add_item(integrations_menu_item)
            add_item(hooks_menu_item)

            true
          end

          override :title
          def title
            _('Settings')
          end

          override :sprite_icon
          def sprite_icon
            'settings'
          end

          private

          override :authorization_subject
          def authorization_subject
            context.current_organization
          end

          override :render_with_abilities
          def render_with_abilities
            %i[access_organization_admin_area]
          end

          def general_menu_item
            build_menu_item(
              title: _('General'),
              link: general_organization_admin_settings_path(context.current_organization),
              active_routes: { controller: 'admin/organizations/settings' },
              item_id: :organization_admin_settings_general
            )
          end

          def integrations_menu_item
            build_menu_item(
              title: _('Integrations'),
              # rubocop:disable Gitlab/AvoidOrganizationUrlRoutes -- We only want to generate org-scoped path here
              link: organization_admin_settings_integrations_path(context.current_organization),
              # rubocop:enable Gitlab/AvoidOrganizationUrlRoutes
              active_routes: { controller: 'admin/organizations/integrations' },
              item_id: :organization_admin_settings_integrations
            ) { can?(context.current_user, :update_integration, context.current_organization) }
          end

          def hooks_menu_item
            build_menu_item(
              title: _('Webhooks'),
              # rubocop:disable Gitlab/AvoidOrganizationUrlRoutes -- Org-scoped path
              link: organization_admin_settings_hooks_path(context.current_organization),
              # rubocop:enable Gitlab/AvoidOrganizationUrlRoutes
              active_routes: { controller: 'admin/organizations/hooks' },
              item_id: :organization_admin_settings_hooks
            ) do
              !Gitlab.com? && # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- Not related to SaaS offerings
                !context.current_organization.default? &&
                ::Feature.enabled?(:org_admin_hooks, context.current_organization) &&
                can?(context.current_user, :read_webhook, context.current_organization)
            end
          end
        end
      end
    end
  end
end
