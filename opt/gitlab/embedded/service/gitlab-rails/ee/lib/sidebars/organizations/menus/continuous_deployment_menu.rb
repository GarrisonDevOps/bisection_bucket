# frozen_string_literal: true

module Sidebars # rubocop:disable Gitlab/BoundedContexts -- overridden class is not inside a bounded context namespace
  module Organizations
    module Menus
      class ContinuousDeploymentMenu < ::Sidebars::Menu
        override :title
        def title
          s_('ContinuousDeployment|Deploy')
        end

        override :sprite_icon
        def sprite_icon
          'deployments'
        end

        override :pick_into_super_sidebar?
        def pick_into_super_sidebar?
          true
        end

        override :configure_menu_items
        def configure_menu_items
          return false unless context.current_user
          return false unless Feature.enabled?(:ai_native_deploy, context.current_user)

          add_item(deploy_applications_menu_item)
          add_item(deploy_environments_menu_item)

          true
        end

        private

        def deploy_applications_menu_item
          link = deploy_applications_organization_path(context.container)
          ::Sidebars::MenuItem.new(
            title: s_('ContinuousDeployment|Applications'),
            link: link,
            super_sidebar_parent: ::Sidebars::Organizations::Menus::ContinuousDeploymentMenu,
            active_routes: { page: link },
            item_id: :deploy_applications
          )
        end

        def deploy_environments_menu_item
          link = deploy_environments_organization_path(context.container)
          ::Sidebars::MenuItem.new(
            title: s_('ContinuousDeployment|Environments'),
            link: link,
            super_sidebar_parent: ::Sidebars::Organizations::Menus::ContinuousDeploymentMenu,
            active_routes: { page: link },
            item_id: :deploy_environments
          )
        end
      end
    end
  end
end
