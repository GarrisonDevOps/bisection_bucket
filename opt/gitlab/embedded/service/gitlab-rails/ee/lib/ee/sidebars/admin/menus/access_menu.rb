# frozen_string_literal: true

module EE
  module Sidebars # rubocop:disable Gitlab/BoundedContexts -- overridden class is not inside a bounded context namespace
    module Admin
      module Menus
        module AccessMenu
          extend ::Gitlab::Utils::Override

          override :configure_menu_items
          def configure_menu_items
            super

            insert_item_before(:deploy_keys, credentials_menu_item)

            true
          end

          private

          def credentials_menu_item
            build_menu_item(
              title: s_('Admin|Credentials'),
              link: admin_credentials_path,
              active_routes: { controller: :credentials },
              item_id: :credentials
            ) { ::License.feature_available?(:credentials_inventory) }
          end
        end
      end
    end
  end
end
