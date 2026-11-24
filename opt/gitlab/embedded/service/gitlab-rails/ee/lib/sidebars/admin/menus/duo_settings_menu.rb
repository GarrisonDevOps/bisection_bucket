# frozen_string_literal: true

module Sidebars
  module Admin
    module Menus
      class DuoSettingsMenu < ::Sidebars::Admin::BaseMenu
        override :link
        def link
          admin_gitlab_duo_path
        end

        override :title
        def title
          _('GitLab Duo')
        end

        override :sprite_icon
        def sprite_icon
          'tanuki-ai'
        end

        override :active_routes
        def active_routes
          {
            controller: [:gitlab_duo, :seat_utilization, :configuration],
            action: %w[show index]
          }
        end
      end
    end
  end
end
