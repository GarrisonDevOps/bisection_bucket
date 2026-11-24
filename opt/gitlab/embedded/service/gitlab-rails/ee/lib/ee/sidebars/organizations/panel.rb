# frozen_string_literal: true

module EE
  module Sidebars # rubocop:disable Gitlab/BoundedContexts -- Existing module
    module Organizations
      module Panel
        extend ::Gitlab::Utils::Override

        override :configure_menus
        def configure_menus
          super

          insert_menu_after(
            ::Sidebars::Organizations::Menus::ManageMenu,
            ::Sidebars::Organizations::Menus::ContinuousDeploymentMenu.new(context)
          )

          insert_menu_after(
            ::Sidebars::Organizations::Menus::ManageMenu,
            ::Sidebars::Organizations::Menus::ArtifactRegistryMenu.new(context)
          )

          insert_menu_after(
            ::Sidebars::Organizations::Menus::ManageMenu,
            ::Sidebars::Organizations::Menus::SecureMenu.new(context)
          )
        end
      end
    end
  end
end
