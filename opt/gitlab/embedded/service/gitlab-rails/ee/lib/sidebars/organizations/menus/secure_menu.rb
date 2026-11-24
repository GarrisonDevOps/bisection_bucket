# frozen_string_literal: true

module Sidebars # rubocop:disable Gitlab/BoundedContexts -- overridden class is not inside a bounded context namespace
  module Organizations
    module Menus
      class SecureMenu < ::Sidebars::Menu
        override :render?
        def render?
          return false unless context.current_user
          return false unless can?(context.current_user, :read_security_resource, context.container)

          security_dashboard_available? || policy_store_available?
        end

        override :title
        def title
          s_('Navigation|Secure')
        end

        override :sprite_icon
        def sprite_icon
          'shield'
        end

        override :pick_into_super_sidebar?
        def pick_into_super_sidebar?
          true
        end

        override :configure_menu_items
        def configure_menu_items
          add_item(security_dashboard_menu_item)
          add_item(policy_store_menu_item)

          true
        end

        private

        def security_dashboard_available?
          Feature.enabled?(:organization_security_dashboard, context.container)
        end

        def policy_store_available?
          context.container.policy_store_experiment_active?
        end

        def security_dashboard_menu_item
          return ::Sidebars::NilMenuItem.new(item_id: :security_dashboard) unless security_dashboard_available?

          link = security_dashboard_organization_path(context.container)

          ::Sidebars::MenuItem.new(
            title: _('Security dashboard'),
            link: link,
            super_sidebar_parent: ::Sidebars::Organizations::Menus::SecureMenu,
            active_routes: { page: link },
            item_id: :security_dashboard
          )
        end

        def policy_store_menu_item
          return ::Sidebars::NilMenuItem.new(item_id: :policy_store) unless policy_store_available?

          ::Sidebars::MenuItem.new(
            title: _('Policy store'),
            link: security_policy_store_organization_path(context.container),
            super_sidebar_parent: ::Sidebars::Organizations::Menus::SecureMenu,
            active_routes: { controller: 'organizations/security/policy_store' },
            item_id: :policy_store
          )
        end
      end
    end
  end
end
