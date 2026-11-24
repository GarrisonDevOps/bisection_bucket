# frozen_string_literal: true

module EE
  module Sidebars # rubocop:disable Gitlab/BoundedContexts -- overridden class is not inside a bounded context namespace
    module Admin
      module Menus
        module MessagesMenu
          extend ::Gitlab::Utils::Override

          override :configure_menu_items
          def configure_menu_items
            return false unless render_targeted_messages_menu_item?

            add_item(broadcast_messages_menu_item)
            add_item(targeted_messages_menu_item)

            true
          end

          private

          def broadcast_messages_menu_item
            build_menu_item(
              title: _('Broadcast Messages'),
              link: admin_broadcast_messages_path,
              active_routes: { controller: :broadcast_messages },
              item_id: :broadcast_messages
            )
          end

          def targeted_messages_menu_item
            build_menu_item(
              title: s_('Admin|Targeted Messages'),
              link: admin_targeted_messages_path,
              active_routes: { controller: :targeted_messages },
              item_id: :targeted_messages
            )
          end

          def render_targeted_messages_menu_item?
            ::Feature.enabled?(:targeted_messages_admin_ui, :instance) &&
              ::Gitlab::Saas.feature_available?(:targeted_messages) &&
              !!context.current_user&.can_admin_all_resources?
          end
        end
      end
    end
  end
end
