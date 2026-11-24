# frozen_string_literal: true

module EE
  module Sidebars # rubocop:disable Gitlab/BoundedContexts -- overridden class is not inside a bounded context namespace
    module Groups
      module Menus
        module PackagesRegistriesMenu
          extend ::Gitlab::Utils::Override

          override :configure_menu_items
          def configure_menu_items
            return false unless super

            add_item(virtual_registry_menu_item)

            true
          end

          private

          def virtual_registry_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :virtual_registry) unless virtual_registry_available?

            ::Sidebars::MenuItem.new(
              title: _('Virtual registry'),
              link: group_virtual_registries_path(context.group),
              super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::DeployMenu,
              active_routes: { controller: %w[groups/virtual_registries
                groups/virtual_registries/maven/registries_and_upstreams
                groups/virtual_registries/maven/registries
                groups/virtual_registries/maven/upstreams
                groups/virtual_registries/container] },
              item_id: :virtual_registry,
              description: _('Cache packages from upstream registries'),
              library_icon: 'archive',
              tier: tier_for(:packages_virtual_registry)
            )
          end

          def virtual_registry_available?
            ::VirtualRegistries.any_registry_available?(context.group, current_user)
          end
        end
      end
    end
  end
end
