# frozen_string_literal: true

module EE
  module Sidebars # rubocop:disable Gitlab/BoundedContexts -- overridden class is not inside a bounded context namespace
    module Admin
      module Menus
        module CiCdMenu
          extend ::Gitlab::Utils::Override

          private

          override :render_with_abilities
          def render_with_abilities
            super + [:read_admin_cicd]
          end
        end
      end
    end
  end
end
