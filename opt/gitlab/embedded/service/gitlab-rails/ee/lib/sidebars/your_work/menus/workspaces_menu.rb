# frozen_string_literal: true

module Sidebars
  module YourWork
    module Menus
      class WorkspacesMenu < ::Sidebars::Menu
        override :link
        def link
          remote_development_workspaces_path(organization_path: nil)
        end

        override :title
        def title
          _('Workspaces')
        end

        override :sprite_icon
        def sprite_icon
          'cloud-terminal'
        end

        override :render?
        def render?
          can?(context.current_user, :access_workspaces_feature)
        end

        override :active_routes
        def active_routes
          { path: 'remote_development/workspaces#index' }
        end
      end
    end
  end
end
