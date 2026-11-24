# frozen_string_literal: true

module EE
  module Projects
    module Security
      module ConfigurationHelper
        extend ::Gitlab::Utils::Override

        override :group_configuration_path
        def group_configuration_path
          group_security_configuration_path(@project.root_ancestor)
        end

        override :duo_settings_configuration_path
        def duo_settings_configuration_path(can_admin_root_group)
          root_ancestor = @project.root_ancestor
          root_ancestor.duo_settings_path if can_admin_root_group && root_ancestor.is_a?(::Group)
        end
      end
    end
  end
end
