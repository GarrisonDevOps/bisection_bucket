# frozen_string_literal: true

module EE
  module Sidebars
    module Explore
      module Panel
        extend ::Gitlab::Utils::Override

        override :configure_menus
        def configure_menus
          super

          insert_menu_after(
            ::Sidebars::Explore::Menus::CatalogMenu,
            ::Sidebars::Explore::Menus::AiCatalogMenu.new(context)
          )

          insert_menu_after(
            ::Sidebars::Explore::Menus::AiCatalogMenu,
            ::Sidebars::Explore::Menus::AnalyticsDashboardsMenu.new(context)
          )
        end
      end
    end
  end
end
