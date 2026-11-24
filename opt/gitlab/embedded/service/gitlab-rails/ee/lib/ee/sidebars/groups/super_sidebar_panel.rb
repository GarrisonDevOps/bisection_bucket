# frozen_string_literal: true

module EE
  module Sidebars # rubocop:disable Gitlab/BoundedContexts -- Existing module
    module Groups
      module SuperSidebarPanel
        extend ::Gitlab::Utils::Override

        override :configure_menus
        def configure_menus
          super

          return unless context.group.root?

          insert_menu_after(
            ::Sidebars::Groups::SuperSidebarMenus::PlanMenu,
            ::Sidebars::Groups::SuperSidebarMenus::DuoAgentsMenu.new(context)
          )
        end
      end
    end
  end
end
