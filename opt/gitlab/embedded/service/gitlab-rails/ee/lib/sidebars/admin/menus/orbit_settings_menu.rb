# frozen_string_literal: true

module Sidebars # rubocop:disable Gitlab/BoundedContexts -- follows the existing Sidebars::Admin::Menus pattern used by sibling menus
  module Admin
    module Menus
      class OrbitSettingsMenu < ::Sidebars::Admin::BaseMenu
        override :link
        def link
          admin_orbit_path
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
          ::Ability.allowed?(context.current_user, :read_knowledge_graph_setting)
        end

        override :active_routes
        def active_routes
          { controller: :orbit }
        end
      end
    end
  end
end
