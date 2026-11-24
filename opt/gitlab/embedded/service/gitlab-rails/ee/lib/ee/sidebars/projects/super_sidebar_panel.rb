# frozen_string_literal: true

module EE
  module Sidebars
    module Projects
      module SuperSidebarPanel
        extend ::Gitlab::Utils::Override

        override :configure_menus
        def configure_menus
          super

          insert_menu_after(
            ::Sidebars::Projects::SuperSidebarMenus::PlanMenu,
            ::Sidebars::Projects::SuperSidebarMenus::DuoAgentsMenu.new(context)
          )
        end
      end
    end
  end
end
