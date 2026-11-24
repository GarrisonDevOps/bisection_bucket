# frozen_string_literal: true

module EE
  module Sidebars # rubocop:disable Gitlab/BoundedContexts -- This has to be named this way.
    module UserSettings
      module Menus
        module AccessMenu
          extend ::Gitlab::Utils::Override

          private

          override :access_tokens_menu_item
          def access_tokens_menu_item
            if ::Gitlab::CurrentSettings.personal_access_tokens_disabled? ||
                context.current_user.enterprise_group&.disable_personal_access_tokens?
              return ::Sidebars::NilMenuItem.new(item_id: :access_tokens)
            end

            super
          end

          override :ssh_keys_menu_item
          def ssh_keys_menu_item
            return ::Sidebars::NilMenuItem.new(item_id: :ssh_keys) if context.current_user.ssh_keys_disabled?

            super
          end
        end
      end
    end
  end
end
