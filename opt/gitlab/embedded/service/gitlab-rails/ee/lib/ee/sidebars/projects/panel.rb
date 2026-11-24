# frozen_string_literal: true

module EE
  module Sidebars
    module Projects
      module Panel
        extend ::Gitlab::Utils::Override

        override :configure_menus
        def configure_menus
          super

          if ::Sidebars::Projects::Menus::IssuesMenu.new(context).show_jira_menu_items?
            remove_menu(::Sidebars::Projects::Menus::ExternalIssueTrackerMenu)
          end

          if ::Sidebars::Projects::Menus::IssuesMenu.new(context).show_zentao_menu_items?
            remove_menu(::Sidebars::Projects::Menus::ZentaoMenu)
          end
        end
      end
    end
  end
end
