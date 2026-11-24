# frozen_string_literal: true

module Sidebars # rubocop:disable Gitlab/BoundedContexts -- sidebar menu follows existing pattern
  module YourWork
    module Menus
      class OrbitMenu < ::Sidebars::Menu
        override :link
        def link
          dashboard_orbit_path(organization_path: nil)
        end

        override :title
        def title
          s_('Orbit|GitLab Orbit')
        end

        override :sprite_icon
        def sprite_icon
          'orbit'
        end

        override :render?
        def render?
          context.current_user &&
            ::Analytics::KnowledgeGraph.enabled_for?(context.current_user)
        end

        override :active_routes
        def active_routes
          { controller: 'dashboard/orbit' }
        end
      end
    end
  end
end
