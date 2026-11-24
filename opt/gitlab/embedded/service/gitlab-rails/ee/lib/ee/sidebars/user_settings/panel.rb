# frozen_string_literal: true

module EE
  module Sidebars
    module UserSettings
      module Panel
        extend ::Gitlab::Utils::Override

        override :configure_menus
        def configure_menus
          super

          insert_menu_after(
            ::Sidebars::UserSettings::Menus::AccountMenu,
            ::Sidebars::UserSettings::Menus::ProfileBillingMenu.new(context)
          )

          insert_menu_after(
            ::Sidebars::UserSettings::Menus::UsageQuotasMenu,
            ::Sidebars::UserSettings::Menus::GitlabCreditsDashboardMenu.new(context)
          )
        end
      end
    end
  end
end
