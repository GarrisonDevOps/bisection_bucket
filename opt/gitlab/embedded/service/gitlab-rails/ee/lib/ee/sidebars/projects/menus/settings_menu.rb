# frozen_string_literal: true

module EE
  module Sidebars
    module Projects
      module Menus
        module SettingsMenu
          extend ::Gitlab::Utils::Override
          include ::WorkItems::SettingsPermissions

          override :configure_menu_items
          def configure_menu_items
            return false unless super

            insert_item_after(:ci_cd, work_item_settings_menu_item)

            true
          end

          def work_item_settings_menu_item
            unless can_access_work_item_settings?(context.project, context.current_user)
              return ::Sidebars::NilMenuItem.new(item_id: :work_items)
            end

            ::Sidebars::MenuItem.new(
              title: _('Work items'),
              link: project_settings_work_items_path(context.project),
              active_routes: { path: %w[projects/settings/work_items#show] },
              item_id: :work_items,
              library_icon: 'settings',
              container_html_options: { 'data-testid': 'project-work-items-settings' }
            )
          end
        end
      end
    end
  end
end
