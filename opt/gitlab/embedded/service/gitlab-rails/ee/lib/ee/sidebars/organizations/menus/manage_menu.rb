# frozen_string_literal: true

module EE
  module Sidebars # rubocop:disable Gitlab/BoundedContexts -- Existing module
    module Organizations
      module Menus
        module ManageMenu
          extend ::Gitlab::Utils::Override

          override :configure_menu_items
          def configure_menu_items
            super

            add_item(organization_access_menu_item)
          end

          private

          def organization_access_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :organization_access) unless show_organization_access_menu_item?

            ::Sidebars::MenuItem.new(
              title: s_('Organization|Organization access'),
              link: access_organization_path(context.container),
              super_sidebar_parent: ::Sidebars::Organizations::Menus::ManageMenu,
              active_routes: { controller: 'organizations/access' },
              item_id: :organization_access
            )
          end

          def show_organization_access_menu_item?
            ::Feature.enabled?(:organization_access_ui, context.current_user) &&
              can?(context.current_user, :read_organization_user, context.container)
          end
        end
      end
    end
  end
end
